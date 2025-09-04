use axum::{extract::Extension, response::Json};

use crate::{dto::UserResponse, entities::user};

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
