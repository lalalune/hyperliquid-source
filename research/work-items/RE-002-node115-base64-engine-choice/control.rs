use base64::{alphabet, engine::fast_portable::{FastPortable, PAD, NO_PAD}};

#[used]
#[link_section = ".check.standard"]
static STANDARD: FastPortable = FastPortable::from(&alphabet::STANDARD, PAD);
#[used]
#[link_section = ".check.url"]
static URL: FastPortable = FastPortable::from(&alphabet::URL_SAFE, PAD);
#[used]
#[link_section = ".check.unpadded"]
static UNPADDED: FastPortable = FastPortable::from(&alphabet::STANDARD, NO_PAD);
