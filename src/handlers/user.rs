use axum::{extract::Extension, response::Json};

use crate::{dto::UserResponse, entities::user};

#[utoipa::path(
    get,
    path = "/user/profile",
    responses(
        (status = 200, description = "User profile retrieved successfully", body = UserResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "User"
)]
pub async fn get_profile(
    Extension(user): Extension<user::Model>,
) -> Json<UserResponse> {
    Json(UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        created_at: user.created_at,
    })
}
