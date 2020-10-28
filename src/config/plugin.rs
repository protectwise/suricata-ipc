pub trait Plugin {
    fn name(&self) -> &str;
    fn path(&self) -> &std::path::Path;
    fn config(&self) -> Option<String>;
}
