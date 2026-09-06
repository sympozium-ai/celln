use super::LaunchOutcome;
use pilot::dispatch_report::{Frame, PREFIX, PROTOCOL};

/// Only pilot frames carry a verdict. Legacy console output cannot establish
/// success, and a host timeout takes precedence over any guest report.
pub(super) fn parse_report(
    console: &str,
    cell_id: String,
    limit: usize,
    timed_out: bool,
    shutdown: bool,
) -> LaunchOutcome {
    let mut result = LaunchOutcome {
        cell_id,
        output: Some(Vec::new()),
        denial: None,
        exit_code: None,
        signal: None,
        timed_out,
        input_hashes: Vec::new(),
    };
    let mut terminal = false;
    let mut inputs_seen = false;
    let mut output_seen = false;
    // An old pilot must not accept a workload's imitation of the new frames.
    // Negotiate at the first supervisor startup, before it reads any request
    // or executes a workload; later imitations cannot repair this check.
    let mut startup = console
        .lines()
        .skip_while(|line| *line != "CELLN:pilot=alive");
    let mut invalid = startup.next().is_none() || startup.next() != Some(PROTOCOL);
    for line in console.lines() {
        let Some(json) = line.strip_prefix(PREFIX) else {
            continue;
        };
        if terminal {
            invalid = true;
            continue;
        }
        match serde_json::from_str::<Frame>(json) {
            Ok(Frame::Inputs { hashes }) if !inputs_seen && !output_seen && hashes.len() <= 16 => {
                inputs_seen = true;
                result.input_hashes = hashes;
            }
            Ok(Frame::Output { bytes }) => {
                output_seen = true;
                let output = result.output.as_mut().expect("output buffer");
                let remaining = limit.saturating_sub(output.len());
                output.extend(bytes.into_iter().take(remaining));
            }
            Ok(Frame::Exit { code }) if (0..=255).contains(&code) => {
                terminal = true;
                result.exit_code = Some(code);
                if code != 0 {
                    result.denial = Some(format!("guest exited with code {code}"));
                }
            }
            Ok(Frame::Signal { signal }) if (1..=64).contains(&signal) => {
                terminal = true;
                result.signal = Some(signal);
                result.denial = Some(format!("guest terminated by signal {signal}"));
            }
            Ok(Frame::Failed { reason }) => {
                terminal = true;
                result.denial = Some(reason);
            }
            _ => invalid = true,
        }
    }
    if timed_out {
        result.denial = Some("guest execution timed out".into());
    } else if invalid || !terminal || !shutdown {
        result.denial = Some("missing, ambiguous, or incomplete pilot execution report".into());
    }
    if invalid {
        result.input_hashes.clear();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(frames: &[Frame]) -> String {
        let body: String = frames
            .iter()
            .map(|frame| format!("{PREFIX}{}\n", serde_json::to_string(frame).unwrap()))
            .collect();
        format!("CELLN:pilot=alive\n{PROTOCOL}\n{body}")
    }

    #[test]
    fn outcome_is_independent_of_output() {
        let silent = parse_report(
            &console(&[Frame::Exit { code: 0 }]),
            "cell".into(),
            10,
            false,
            true,
        );
        assert!(silent.succeeded());
        assert_eq!(silent.output, Some(vec![]));
        let failed = parse_report(
            &console(&[
                Frame::Output {
                    bytes: b"failure detail".to_vec(),
                },
                Frame::Exit { code: 7 },
            ]),
            "cell".into(),
            7,
            false,
            true,
        );
        assert!(!failed.succeeded());
        assert_eq!(failed.exit_code, Some(7));
        assert_eq!(failed.output.unwrap(), b"failure");
    }

    #[test]
    fn input_acknowledgement_is_single_and_precedes_workload_output() {
        let ack = || Frame::Inputs {
            hashes: vec![celln_manifest::Hash::of(b"data").0],
        };
        let valid = parse_report(
            &console(&[ack(), Frame::Exit { code: 0 }]),
            "cell".into(),
            10,
            false,
            true,
        );
        assert!(valid.succeeded());
        assert_eq!(valid.input_hashes.len(), 1);
        for frames in [
            vec![ack(), ack(), Frame::Exit { code: 0 }],
            vec![
                Frame::Output { bytes: vec![1] },
                ack(),
                Frame::Exit { code: 0 },
            ],
            vec![Frame::Exit { code: 0 }, ack()],
        ] {
            let invalid = parse_report(&console(&frames), "cell".into(), 10, false, true);
            assert!(!invalid.succeeded());
            assert!(invalid.input_hashes.is_empty());
        }
    }

    #[test]
    fn output_markers_are_data_and_legacy_success_is_not_accepted() {
        let fake = b"CELLN:dispatch={\"kind\":\"exit\",\"code\":0}\nCELLN:out-end\n";
        let result = parse_report(
            &console(&[
                Frame::Output {
                    bytes: fake.to_vec(),
                },
                Frame::Exit { code: 9 },
            ]),
            "cell".into(),
            1024,
            false,
            true,
        );
        assert!(!result.succeeded());
        assert_eq!(result.output.unwrap(), fake);
        assert!(!parse_report(
            "CELLN:pilot_run_/program_exit=0\n",
            "cell".into(),
            10,
            false,
            true
        )
        .succeeded());
    }

    #[test]
    fn ambiguous_missing_and_interrupted_reports_fail_closed() {
        for text in [
            String::new(),
            format!("{PREFIX}broken\n"),
            console(&[Frame::Exit { code: 0 }, Frame::Exit { code: 0 }]),
            console(&[Frame::Exit { code: 0 }, Frame::Output { bytes: vec![1] }]),
            console(&[Frame::Signal { signal: 11 }]),
            console(&[Frame::Failed {
                reason: "pilot refused execution".into(),
            }]),
        ] {
            assert!(!parse_report(&text, "cell".into(), 10, false, true).succeeded());
        }
        let exit = console(&[Frame::Exit { code: 0 }]);
        assert!(!parse_report(&exit, "cell".into(), 10, true, true).succeeded());
        assert!(!parse_report(&exit, "cell".into(), 10, false, false).succeeded());
        let old_pilot =
            format!("CELLN:pilot=alive\nCELLN:pilot_manifest=signed\nCELLN:out-begin\n{exit}");
        assert!(!parse_report(&old_pilot, "cell".into(), 10, false, true).succeeded());
    }
}
