//! Synthetic stdin adapter, not a node protocol parser or original ABI.
use node115_perp_tier_selector::{select, Frontier, Inputs, Node, RingRow, RowOrigin, Storage};
use std::fmt::Debug;
use std::io::{self, BufRead, Write};
use std::str::FromStr;
fn csv<T: FromStr>(s: &str) -> Vec<T>
where
    T::Err: Debug,
{
    if s == "-" {
        Vec::new()
    } else {
        s.split(',').map(|x| x.parse().unwrap()).collect()
    }
}
fn fields(s: &str) -> Vec<[u64; 3]> {
    if s == "-" {
        Vec::new()
    } else {
        s.split('/').map(|v| csv(v).try_into().unwrap()).collect()
    }
}
struct OwnedNode {
    keys: Vec<u32>,
    children: Vec<usize>,
    fields: Vec<[u64; 3]>,
}
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 8);
        let owned: Vec<OwnedNode> = if v[6] == "-" {
            Vec::new()
        } else {
            v[6].split(';')
                .map(|entry| {
                    let f: Vec<_> = entry.split(':').collect();
                    assert_eq!(f.len(), 3);
                    OwnedNode {
                        keys: csv(f[0]),
                        children: csv(f[1]),
                        fields: fields(f[2]),
                    }
                })
                .collect()
        };
        let nodes: Vec<Node> = owned
            .iter()
            .map(|n| Node {
                keys: &n.keys,
                children: &n.children,
                fields: &n.fields,
            })
            .collect();
        let (head, count, ring_rows) = if v[7] == "!" {
            (0, 0, Vec::new())
        } else {
            let f: Vec<_> = v[7].split(':').collect();
            assert_eq!(f.len(), 4);
            let keys: Vec<u32> = csv(f[2]);
            let values = fields(f[3]);
            assert_eq!(keys.len(), values.len());
            (
                f[0].parse().unwrap(),
                f[1].parse().unwrap(),
                keys.into_iter()
                    .zip(values)
                    .map(|(key, fields)| RingRow { key, fields })
                    .collect::<Vec<_>>(),
            )
        };
        let descriptor: u64 = v[1].parse().unwrap();
        let root: i64 = v[4].parse().unwrap();
        let storage = if descriptor == 1 << 63 {
            Storage::Tree {
                root: if root < 0 { None } else { Some(root as usize) },
                height: v[5].parse().unwrap(),
                nodes: &nodes,
            }
        } else {
            assert_eq!(descriptor as usize, ring_rows.len());
            Storage::Ring {
                head,
                count,
                rows: &ring_rows,
            }
        };
        match select(Inputs {
            key: v[0].parse().unwrap(),
            guard: v[2].parse().unwrap(),
            retained: v[3].parse().unwrap(),
            storage,
        }) {
            None => writeln!(out, "[\"D\"]").unwrap(),
            Some(Frontier::BeforeDiagnostic) => writeln!(out, "[\"M\"]").unwrap(),
            Some(Frontier::BeforeInitialize { key, retained }) => {
                writeln!(out, "[\"I\",{key},{retained}]").unwrap()
            }
            Some(Frontier::Returned { words, origin }) => {
                write!(out, "[\"R\",{},{},", words[0], words[1]).unwrap();
                match origin {
                    RowOrigin::Global { index, byte_offset } => {
                        write!(out, "[\"G\",{index},{byte_offset}]").unwrap()
                    }
                    RowOrigin::Tree {
                        node,
                        slot,
                        byte_offset,
                    } => write!(out, "[\"T\",{node},{slot},{byte_offset}]").unwrap(),
                    RowOrigin::Ring {
                        physical,
                        byte_offset,
                    } => write!(out, "[\"B\",{physical},{byte_offset}]").unwrap(),
                }
                writeln!(out, ",{}]", words[2]).unwrap();
            }
        }
    }
}
