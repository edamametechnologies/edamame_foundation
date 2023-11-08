pub static EDAMAME_HELPER_SENTRY: &str = env!("EDAMAME_HELPER_SENTRY");
pub static EDAMAME_APP_SENTRY: &str = env!("EDAMAME_APP_SENTRY");

pub fn init_app_sentry() {

    // Init sentry
    let _guard = sentry::init((EDAMAME_APP_SENTRY, sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
}

pub fn init_helper_sentry() {

    // Init sentry
    let _guard = sentry::init((EDAMAME_HELPER_SENTRY, sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
}