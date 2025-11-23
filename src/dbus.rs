#[zbus::proxy(
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    interface = "org.freedesktop.login1.Manager"
)]
pub trait FdoLoginService {
    #[zbus(signal)]
    fn prepare_for_sleep(&self, prepare_for_sleep: bool);
}

#[zbus::proxy(
    default_service = "org.freedesktop.ScreenSaver",
    default_path = "/org/freedesktop/ScreenSaver",
    interface = "org.freedesktop.ScreenSaver"
)]
pub trait FdoScreenSaverService {
    #[zbus(signal)]
    fn active_changed(&self, active: bool);
}
