extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;

use std::fmt::Write;
use std::fmt;
use std::collections::HashMap;
use std::collections::hash_map::Entry::*;

struct HexDisplay<'a>(&'a [u8]);

impl<'a> fmt::Display for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in self.0 {
            try!(write!(f, "{:02X}", i));
        }
        Ok(())
    }
}

fn truncated_hash(data: &str) -> [u8; 6] {
    let full_hash = oneshot_hash(data);
    [full_hash[26], full_hash[27], full_hash[28], full_hash[29], full_hash[30], full_hash[31]]
}

fn oneshot_hash(data: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input_str(data);
    let mut full_hash = [0u8; 32]; // could use mem::uninitialized
    hasher.result(&mut full_hash);
    full_hash
}


fn main() {
    let mut bigtable = HashMap::<[u8; 6], usize>::new();
    let mut rng = rand::weak_rng();
    
    const LEN: usize = 8;

    let mut bigstring = rng.gen_ascii_chars()
        .take(LEN)
        .collect::<String>();
     
    for i in 0usize.. {
        // Need a block to end borrow of bigstring
        {
            let hstr = &bigstring[i .. i+LEN];
            let thex = truncated_hash(hstr);
            
            match bigtable.entry(thex) {
                Occupied(mut entry) => {
                    let old_idx = entry.insert(i);
                    let old_str = &bigstring[old_idx..old_idx+LEN];
                    let new_str = hstr;
                    if new_str != old_str {
                        let old_hash = oneshot_hash(old_str);
                        let new_hash = oneshot_hash(hstr);
                        if old_hash[25] & 0x3 == new_hash[25] & 0x3 {
                            println!("\t-> {:08}", i);
                            println!("EVO: {} .. {} -> {}", old_str, new_str, HexDisplay(&thex));
                            break;
                        }
                        else {
                            println!("?");
                        }
                    }
                    else {
                        print!("*");
                    }
                },
                Vacant(entry) => {
                    entry.insert(i);
                },
            }
        }
        
        bigstring.push(rng.gen_ascii_chars().next().unwrap());
        
        if i % 2000000 == 0 {
            println!("\t-> {:08}", i);
        }
    }
}
