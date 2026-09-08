use std::collections::BTreeMap;

use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn with_local_scope<F, R>(&mut self, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut Self) -> Result<R, String>,
    {
        self.local_scopes.push(BTreeMap::new());
        let result = f(self);
        self.local_scopes.pop();
        result
    }

    pub(super) fn declare_local(&mut self, source_name: String) -> Result<String, String> {
        let Some(scope) = self.local_scopes.last_mut() else {
            return Err(self.err("internal parser scope error"));
        };
        if scope.contains_key(&source_name) {
            return Err(self.err(&format!("local '{}' is already declared in this scope", source_name)));
        }
        let internal_name = format!("__rt_l{}_{}", self.next_local_id, source_name);
        self.next_local_id += 1;
        scope.insert(source_name, internal_name.clone());
        Ok(internal_name)
    }

    pub(super) fn resolve_local(&self, source_name: &str) -> Option<String> {
        self.local_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(source_name).cloned())
    }

    pub(super) fn resolve_local_name_or_source(&self, source_name: String) -> String {
        self.resolve_local(&source_name).unwrap_or(source_name)
    }
}
