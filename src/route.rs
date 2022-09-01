use crate::auth::Session;

// Dummy function, session contains all the username parameters and password
// TODO: May be better to use an enum here for the different options
pub fn get_route_type(_session: &Session) -> String {
    "dummy".to_string()
}
