use arbitrary::Unstructured;
use wgproto::PrivateKey;
use wgproto::PublicKey;

pub fn arbitrary_public_key(u: &mut Unstructured<'_>) -> Result<PublicKey, arbitrary::Error> {
    let private_key: PrivateKey = u.arbitrary::<[u8; 32]>()?.into();
    Ok((&private_key).into())
}
