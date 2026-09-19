//! What one check found.

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Could the probe measure at all? A sensor that cannot measure must not
    /// look like a quiet day.
    pub success: bool,
    /// The verdict. `None`: this probe passes none, or there was nothing to
    /// judge (a machine that is not running).
    pub ok: Option<bool>,
    /// The numbers behind the verdict, each with the item it belongs to.
    pub values: Vec<(String, f64)>,
    /// For a human who runs it by hand.
    pub note: Option<String>,
}

impl Outcome {
    pub fn failed(note: impl Into<String>) -> Outcome {
        Outcome {
            success: false,
            ok: None,
            values: Vec::new(),
            note: Some(note.into()),
        }
    }

    pub fn judged(ok: bool, values: Vec<(String, f64)>, note: Option<String>) -> Outcome {
        Outcome {
            success: true,
            ok: Some(ok),
            values,
            note,
        }
    }
}
