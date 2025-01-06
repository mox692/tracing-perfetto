#![forbid(unsafe_code)]

use bytes::BytesMut;
use idl::InternedData;
use prost::Message;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;
use tracing::Event;
use tracing::Id;
use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

pub mod error;
pub mod external;

mod idl {
    include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
}

thread_local! {
    static THREAD_TRACK_UUID: AtomicU64 = AtomicU64::new(rand::random::<u64>());
    static THREAD_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);
}

// This is thread safe, since duplicated descriptor will be combined into one by perfetto.
static PROCESS_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);

/// A `Layer` that records span as perfetto's
/// `TYPE_SLICE_BEGIN`/`TYPE_SLICE_END`, and event as `TYPE_INSTANT`.
///
/// `PerfettoLayer` will output the records as encoded [protobuf messages](https://github.com/google/perfetto).
pub struct PerfettoLayer<W = fn() -> std::io::Stdout> {
    sequence_id: SequenceId,
    track_uuid: TrackUuid,
    writer: W,
    config: Config,
    pid: i32,
    // TODO: move to tokio's layer
    aslr_offset: Option<u64>,
}

/// Writes encoded records into provided instance.
///
/// This is implemented for types implements [`MakeWriter`].
pub trait PerfettoWriter {
    fn write_log(&self, buf: BytesMut) -> std::io::Result<()>;
}

impl<W: for<'writer> MakeWriter<'writer> + 'static> PerfettoWriter for W {
    fn write_log(&self, buf: BytesMut) -> std::io::Result<()> {
        self.make_writer().write_all(&buf)
    }
}

#[derive(Default)]
struct Config {
    debug_annotations: bool,
    filter: Option<fn(&str) -> bool>,
}

impl<W: PerfettoWriter> PerfettoLayer<W> {
    pub fn new(writer: W) -> Self {
        Self {
            sequence_id: SequenceId::new(rand::random()),
            track_uuid: TrackUuid::new(rand::random()),
            writer,
            config: Config::default(),
            // todo: change the way to get an offset
            pid: std::process::id() as i32,
            aslr_offset: read_aslr_offset().ok(),
        }
    }

    /// Configures whether or not spans/events shoulde be recored with their metadata and fields.
    pub fn with_debug_annotations(mut self, value: bool) -> Self {
        self.config.debug_annotations = value;
        self
    }

    /// Configures whether or not spans/events be recored based on the occurrence of a field name.
    ///
    /// Sometimes, not all the events/spans should be treated as perfetto trace, you can append a
    /// field to indicate that this even/span should be captured into trace:
    ///
    /// ```rust
    /// use tracing_perfetto::PerfettoLayer;
    /// use tracing_subscriber::{layer::SubscriberExt, Registry, prelude::*};
    ///
    /// let layer = PerfettoLayer::new(std::fs::File::open("/tmp/test.pftrace").unwrap())
    ///                 .with_filter_by_marker(|field_name| field_name == "perfetto");
    /// tracing_subscriber::registry().with(layer).init();
    ///
    /// // this event will be record, as it contains a `perfetto` field
    /// tracing::info!(perfetto = true, my_bool = true);
    ///
    /// // this span will be record, as it contains a `perfetto` field
    /// #[tracing::instrument(fields(perfetto = true))]
    /// fn to_instr() {
    ///
    ///   // this event will be ignored
    ///   tracing::info!(my_bool = true);
    /// }
    /// ```
    pub fn with_filter_by_marker(mut self, filter: fn(&str) -> bool) -> Self {
        self.config.filter = Some(filter);
        self
    }

    fn append_thread_descriptor(&self, trace: &mut idl::Trace) {
        let thread_first_frame_sent =
            THREAD_DESCRIPTOR_SENT.with(|v| v.fetch_or(true, Ordering::SeqCst));
        let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
        if !thread_first_frame_sent {
            let mut packet = idl::TracePacket::default();
            packet.optional_trusted_uid = Some(idl::trace_packet::OptionalTrustedUid::TrustedUid(
                self.sequence_id.get() as _,
            ));
            let thread = create_thread_descriptor(self.pid).into();
            let track_desc = create_track_descriptor(
                thread_track_uuid.into(),
                self.track_uuid.get().into(),
                std::thread::current().name(),
                None,
                thread,
                None,
            );
            packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_desc));
            trace.packet.push(packet);
        }
    }

    fn append_process_descriptor(&self, trace: &mut idl::Trace) {
        let process_first_frame_sent = PROCESS_DESCRIPTOR_SENT.fetch_or(true, Ordering::SeqCst);
        if !process_first_frame_sent {
            let mut packet = idl::TracePacket::default();
            packet.optional_trusted_uid = Some(idl::trace_packet::OptionalTrustedUid::TrustedUid(
                self.sequence_id.get() as _,
            ));
            let process = create_process_descriptor(self.pid).into();
            let track_desc = create_track_descriptor(
                self.track_uuid.get().into(),
                None,
                None::<&str>,
                process,
                None,
                None,
            );
            packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_desc));
            trace.packet.push(packet);
        }
    }

    fn write_log(&self, log: idl::Trace) {
        let mut buf = BytesMut::new();
        let mut log = log;

        self.append_process_descriptor(&mut log);
        self.append_thread_descriptor(&mut log);

        let Ok(_) = log.encode(&mut buf) else {
            return;
        };
        _ = self.writer.write_log(buf);
    }
}

struct SequenceId(u64);

impl SequenceId {
    fn new(n: u64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0
    }
}

struct TrackUuid(u64);

impl TrackUuid {
    fn new(n: u64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0
    }
}

struct PerfettoVisitor {
    perfetto: bool,
    name: Option<String>,
    is_runtask: bool,
    filter: fn(&str) -> bool,
}

impl PerfettoVisitor {
    fn new(filter: fn(&str) -> bool) -> PerfettoVisitor {
        Self {
            filter,
            perfetto: false,
            name: None,
            is_runtask: false,
        }
    }
}

impl Visit for PerfettoVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if (self.filter)(field.name()) {
            self.perfetto = true;
        }
        let field_name = field.name();
        if field_name == "name" {
            self.name = Some(format!("{:?}", value));
        }
        if field_name == "tokio_runtime_event" {
            if format!("{:?}", value).contains("run_task") {
                self.is_runtask = true;
            }
        }
    }
}

impl<W, S: Subscriber> Layer<S> for PerfettoLayer<W>
where
    S: for<'a> LookupSpan<'a>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };

        let name = &mut None;
        let is_runtask = &mut false;
        let enabled = self
            .config
            .filter
            .map(|f| {
                let mut visitor = PerfettoVisitor::new(f);
                attrs.record(&mut visitor);
                *name = visitor.name;
                *is_runtask = visitor.is_runtask;
                visitor.perfetto
            })
            .unwrap_or(true);

        if !enabled {
            return;
        }

        let mut debug_annotations = DebugAnnotations::default();
        if self.config.debug_annotations {
            attrs.record(&mut debug_annotations);
        }

        let mut packet = idl::TracePacket::default();
        let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
        let mut name = name.clone().map_or_else(|| span.name().to_string(), |v| v);
        if *is_runtask {
            name = format!("task {name}");
        }
        let event = create_event(
            thread_track_uuid,
            Some(&name),
            span.metadata().file().zip(span.metadata().line()),
            debug_annotations,
            Some(idl::track_event::Type::SliceBegin),
        );
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.trusted_pid = Some(self.pid);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        packet.interned_data = Some(InternedData {
            debug_annotation_names: vec![idl::DebugAnnotationName {
                iid: Some(1),
                name: Some("aslr_offset".to_string()),
            }],
            debug_annotation_string_values: vec![idl::InternedString {
                iid: Some(1),
                str: self.aslr_offset.map(|v| {
                    v.to_string()
                        .chars()
                        .map(|c| c.to_digit(10).unwrap() as u8)
                        .collect()
                }),
            }],
            ..Default::default()
        });

        span.extensions_mut().insert(idl::Trace {
            packet: vec![packet],
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let name = &mut None;
        let is_runtask = &mut false;
        let enabled = self
            .config
            .filter
            .map(|f| {
                let mut visitor = PerfettoVisitor::new(f);
                event.record(&mut visitor);
                *name = visitor.name;
                *is_runtask = visitor.is_runtask;
                visitor.perfetto
            })
            .unwrap_or_default();

        if !enabled {
            return;
        }

        let metadata = event.metadata();
        let location = metadata.file().zip(metadata.line());

        let mut debug_annotations = DebugAnnotations::default();

        if self.config.debug_annotations {
            event.record(&mut debug_annotations);
        }

        let mut name = name
            .clone()
            .map_or_else(|| metadata.name().to_string(), |v| v);
        if *is_runtask {
            name = format!("task {name}");
        }
        let track_event = THREAD_TRACK_UUID.with(|id| {
            create_event(
                id.load(Ordering::Relaxed),
                Some(&name),
                location,
                debug_annotations,
                Some(idl::track_event::Type::Instant),
            )
        });
        let mut packet = idl::TracePacket::default();
        packet.data = Some(idl::trace_packet::Data::TrackEvent(track_event));
        packet.trusted_pid = Some(self.pid);
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        packet.interned_data = Some(InternedData {
            debug_annotation_names: vec![idl::DebugAnnotationName {
                iid: Some(1),
                name: Some("aslr_offset".to_string()),
            }],
            debug_annotation_string_values: vec![idl::InternedString {
                iid: Some(1),
                str: self.aslr_offset.map(|v| {
                    v.to_string()
                        .chars()
                        .map(|c| c.to_digit(10).unwrap() as u8)
                        .collect()
                }),
            }],
            ..Default::default()
        });

        if let Some(span) = ctx.event_span(event) {
            if let Some(trace) = span.extensions_mut().get_mut::<idl::Trace>() {
                trace.packet.push(packet);
                return;
            }
        }
        let trace = idl::Trace {
            packet: vec![packet],
        };
        self.write_log(trace);
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };

        let mut ext = span.extensions_mut();
        let Some(trace) = ext.get_mut::<idl::Trace>() else {
            return;
        };

        for packet in trace.packet.iter_mut() {
            if let Some(idl::trace_packet::Data::TrackEvent(ref mut e)) = &mut packet.data {
                // track_event::Type::SliceBegin
                if e.r#type == Some(1) {
                    let mut debug_annotations = DebugAnnotations::default();
                    values.record(&mut debug_annotations);
                    e.debug_annotations
                        .append(&mut debug_annotations.annotations)
                }
            }
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };

        let Some(mut trace) = span.extensions_mut().remove::<idl::Trace>() else {
            return;
        };

        let debug_annotations = DebugAnnotations::default();
        let mut packet = idl::TracePacket::default();
        let meta = span.metadata();

        let Some(Some(idl::trace_packet::Data::TrackEvent(te))) =
            trace.packet.get(0).map(|p| &p.data)
        else {
            return;
        };

        let Some(idl::track_event::NameField::Name(name_str)) = te.name_field.as_ref() else {
            return;
        };

        let has_runtask = te
            .debug_annotations
            .iter()
            .find(|a| {
                a.name_field.as_ref()
                    == Some(&idl::debug_annotation::NameField::Name(
                        "run_task".to_string(),
                    ))
            })
            .is_some();

        let event = THREAD_TRACK_UUID.with(|id| {
            if has_runtask {
                create_event(
                    id.load(Ordering::Relaxed),
                    Some(format!("task {name_str}").as_str()),
                    meta.file().zip(meta.line()),
                    debug_annotations,
                    Some(idl::track_event::Type::SliceEnd),
                )
            } else {
                create_event(
                    id.load(Ordering::Relaxed),
                    Some(name_str),
                    meta.file().zip(meta.line()),
                    debug_annotations,
                    Some(idl::track_event::Type::SliceEnd),
                )
            }
        });
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.trusted_pid = Some(self.pid);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        packet.interned_data = Some(InternedData {
            debug_annotation_names: vec![idl::DebugAnnotationName {
                iid: Some(1),
                name: Some("aslr_offset".to_string()),
            }],
            debug_annotation_string_values: vec![idl::InternedString {
                iid: Some(1),
                str: self.aslr_offset.map(|v| {
                    v.to_string()
                        .chars()
                        .map(|c| c.to_digit(10).unwrap() as u8)
                        .collect()
                }),
            }],
            ..Default::default()
        });

        trace.packet.push(packet);

        self.write_log(trace);
    }
}

fn create_thread_descriptor(pid: i32) -> idl::ThreadDescriptor {
    let mut thread = idl::ThreadDescriptor::default();
    thread.pid = Some(pid);
    thread.tid = Some(thread_id::get() as _);
    thread.thread_name = std::thread::current().name().map(|n| n.to_string());
    thread
}

fn create_process_descriptor(pid: i32) -> idl::ProcessDescriptor {
    let mut process = idl::ProcessDescriptor::default();
    process.pid = Some(pid);
    process
}

fn create_track_descriptor(
    uuid: Option<u64>,
    parent_uuid: Option<u64>,
    name: Option<impl AsRef<str>>,
    process: Option<idl::ProcessDescriptor>,
    thread: Option<idl::ThreadDescriptor>,
    counter: Option<idl::CounterDescriptor>,
) -> idl::TrackDescriptor {
    let mut desc = idl::TrackDescriptor::default();
    desc.uuid = uuid;
    desc.parent_uuid = parent_uuid;
    desc.static_or_dynamic_name = name
        .map(|s| s.as_ref().to_string())
        .map(idl::track_descriptor::StaticOrDynamicName::Name);
    desc.process = process;
    desc.thread = thread;
    desc.counter = counter;
    desc
}

fn create_event(
    track_uuid: u64,
    name: Option<&str>,
    location: Option<(&str, u32)>,
    debug_annotations: DebugAnnotations,
    r#type: Option<idl::track_event::Type>,
) -> idl::TrackEvent {
    let mut event = idl::TrackEvent::default();
    event.track_uuid = Some(track_uuid);
    if let Some(name) = name {
        event.name_field = Some(idl::track_event::NameField::Name(name.to_string()));
    }
    if let Some(t) = r#type {
        event.set_type(t);
    }
    if !debug_annotations.annotations.is_empty() {
        event.debug_annotations = debug_annotations.annotations;
    }
    if let Some((file, line)) = location {
        let mut source_location = idl::SourceLocation::default();
        source_location.file_name = Some(file.to_owned());
        source_location.line_number = Some(line);
        let location = idl::track_event::SourceLocationField::SourceLocation(source_location);
        event.source_location_field = Some(location);
    }
    event
}

#[derive(Default)]
struct DebugAnnotations {
    annotations: Vec<idl::DebugAnnotation>,
}

impl Visit for DebugAnnotations {
    fn record_bool(&mut self, field: &Field, value: bool) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::BoolValue(value));
        self.annotations.push(annotation);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(value.to_string()));
        self.annotations.push(annotation);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::DoubleValue(value));
        self.annotations.push(annotation);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::IntValue(value));
        self.annotations.push(annotation);
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(value.to_string()));
        self.annotations.push(annotation);
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(value.to_string()));
        self.annotations.push(annotation);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::IntValue(value as _));
        self.annotations.push(annotation);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(format!(
            "{value:?}"
        )));
        self.annotations.push(annotation);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(format!(
            "{value}"
        )));
        self.annotations.push(annotation);
    }
}

#[cfg(target_os = "linux")]
pub fn read_aslr_offset() -> crate::error::Result<u64> {
    use procfs::process::{MMapPath, Process};

    fn read_aslr_offset_inner() ->  procfs::ProcResult<u64> {
        let process = Process::myself()?;
        let exe = process.exe()?;
        let maps = &process.maps()?;
        let mut addresses: Vec<u64> = maps
            .iter()
            .filter_map(|map| {
                let MMapPath::Path(bin_path) = &map.pathname else {
                    return None;
                };
                if bin_path != &exe {
                    return None;
                }

                return Some(map.address.0);
            })
            .collect();

        addresses.sort();
        if let Some(addr) = addresses.get(0) {
            Ok(*addr)
        } else {
            panic!("no memory map error.")
        }
    }

    let result = read_aslr_offset_inner();
    result.map_err(|e| {
        crate::error::TracingPerfettoError::new("TracingPerfettoError:", Box::new(e))
    })
}


#[cfg(not(target_os = "linux"))]
pub fn read_aslr_offset() -> crate::error::Result<u64> {
    // Not supported.
    Ok(0)
}
