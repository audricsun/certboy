#[derive(Debug)]
#[allow(dead_code)]
pub enum OperationMode {
    RootCa,
    IntermediateCa,
    Certificate,
    Help,
    Error(String),
}
