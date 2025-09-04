use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    auth::auth_middleware,
    handlers::{get_profile, login, register},
    state::AppState,
};

pub fn create_routes(app_state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    let protected_routes = Router::new()
        .route("/profile", get(get_profile))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/user", protected_routes)
        .with_state(app_state)
}
