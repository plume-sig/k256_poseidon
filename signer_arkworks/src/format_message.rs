use plume_arkworks::Affine;

/// Returns `None` if `pk` is the identity element.
pub fn form_plume_msg(msg: &[u8], pk: &Affine) -> Option<Vec<u8>> {
    Some(
        [msg, &plume_arkworks::sec1_affine(pk)?].concat()
        // .try_into().expect("`Vec` as the most ubiquitous one will always able to accomodate this, and the types are matched precisely")
    )
}
