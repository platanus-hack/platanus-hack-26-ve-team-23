//! Merkle tree over a batch of events (ADR-0025), shaped as in RFC 6962:
//! the tree splits at the largest power of two smaller than its size, so no
//! leaf is duplicated, and leaves and nodes carry different domain tags so a
//! node can never be passed off as a leaf.

use sha2::{Digest as _, Sha256};

use crate::{chain::Digest, event::Event};

const LEAF: &[u8] = b"guardian.leaf.v1";
const NODE: &[u8] = b"guardian.node.v1";

/// Root of an empty batch (a head signed before any event).
pub const EMPTY_ROOT: Digest = [0u8; 32];

pub fn leaf_hash(event: &Event) -> Digest {
    Sha256::new()
        .chain_update(LEAF)
        .chain_update(event.encode())
        .finalize()
        .into()
}

fn node_hash(left: &Digest, right: &Digest) -> Digest {
    Sha256::new()
        .chain_update(NODE)
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Largest power of two strictly smaller than `n` (n >= 2).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Root over leaf hashes.
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => EMPTY_ROOT,
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Sibling hashes from the leaf at `index` up to the root.
pub fn proof(leaves: &[Digest], index: usize) -> Option<Vec<Digest>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    collect(leaves, index, &mut path);
    Some(path)
}

fn collect(leaves: &[Digest], index: usize, path: &mut Vec<Digest>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    if index < k {
        collect(&leaves[..k], index, path);
        path.push(root(&leaves[k..]));
    } else {
        collect(&leaves[k..], index - k, path);
        path.push(root(&leaves[..k]));
    }
}

/// Checks that `leaf` is entry `index` of a batch of `size` leaves whose
/// root is `expected`. `size` must come from the signed head, never from
/// the party presenting the proof; `SignedHead::verify_inclusion` does that.
pub fn verify(
    leaf: &Digest,
    index: usize,
    size: usize,
    path: &[Digest],
    expected: &Digest,
) -> bool {
    if index >= size {
        return false;
    }
    fold(leaf, index, size, path)
        .is_some_and(|(computed, rest)| rest.is_empty() && &computed == expected)
}

/// Recomputes the root bottom-up, consuming the path from its start (the
/// sibling nearest the leaf). Returns the root and the unused path.
fn fold<'a>(
    leaf: &Digest,
    index: usize,
    size: usize,
    path: &'a [Digest],
) -> Option<(Digest, &'a [Digest])> {
    if size <= 1 {
        return Some((*leaf, path));
    }
    let k = split(size);
    if index < k {
        let (left, rest) = fold(leaf, index, k, path)?;
        let (sibling, rest) = rest.split_first()?;
        Some((node_hash(&left, sibling), rest))
    } else {
        let (right, rest) = fold(leaf, index - k, size - k, path)?;
        let (sibling, rest) = rest.split_first()?;
        Some((node_hash(sibling, &right), rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn leaves(n: u64) -> Vec<Digest> {
        (0..n)
            .map(|seq| {
                leaf_hash(&Event {
                    seq,
                    timestamp_ms: seq,
                    kind: EventKind::Decision,
                    payload: vec![seq as u8; 3],
                })
            })
            .collect()
    }

    #[test]
    fn every_leaf_proves_for_many_sizes() {
        for n in 1..=17 {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..l.len() {
                let p = proof(&l, i).unwrap();
                assert!(verify(&l[i], i, l.len(), &p, &r), "size {n} index {i}");
            }
        }
    }

    #[test]
    fn a_wrong_leaf_index_or_root_fails() {
        let l = leaves(7);
        let r = root(&l);
        let p = proof(&l, 3).unwrap();
        assert!(!verify(&l[4], 3, 7, &p, &r));
        assert!(!verify(&l[3], 2, 7, &p, &r));
        assert!(!verify(&l[3], 3, 7, &p, &[1u8; 32]));
        assert!(!verify(&l[3], 9, 7, &p, &r));
        // A size that changes the tree's shape changes the path length.
        let p5 = proof(&l, 5).unwrap();
        assert!(verify(&l[5], 5, 7, &p5, &r));
        assert!(!verify(&l[5], 5, 6, &p5, &r));
    }

    #[test]
    fn an_inner_node_cannot_pass_as_an_event_of_the_signed_batch() {
        // The verifier takes the batch size from the signed head (4 here)
        // and hashes the event itself, so a node offered as a leaf of a
        // smaller tree does not verify.
        let l = leaves(4);
        let r = root(&l);
        let left_node = root(&l[..2]);
        let right_node = root(&l[2..]);
        assert!(!verify(&left_node, 0, 4, &[right_node], &r));
    }

    #[test]
    fn edge_sizes() {
        assert_eq!(root(&[]), EMPTY_ROOT);
        let one = leaves(1);
        assert_eq!(root(&one), one[0]);
        assert_eq!(proof(&one, 0).unwrap(), Vec::<Digest>::new());
        assert!(proof(&one, 1).is_none());
    }
}
