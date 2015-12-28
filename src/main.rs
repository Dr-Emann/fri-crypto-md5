extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;

use std::fmt::Write;
use std::char;
use std::collections::HashMap;


fn hexprint(raw: &[u8; 6]) {
    let mut s = String::new();
    for &byte in raw.iter() {
        write!(&mut s, "{:02X}", byte).unwrap();
    }
    println!("{}", s);
}

fn truncate(raw: &[u8]) -> [u8; 6] {
    [raw[26], raw[27], raw[28], raw[29], raw[30], raw[31]]
}

fn to_valid_char(b: u8) -> char {
	let b_32 = (b % 62) as u32;
	match b_32 {
		0  ... 25 => char::from_u32(b_32 + 65).unwrap(),
		26 ... 51 => char::from_u32(b_32 - 26 + 97).unwrap(),
		_         => char::from_u32(b_32 - 52 + 48).unwrap()
	}
}

fn main() {
    let mut bigtable = HashMap::<[u8; 6], usize>::new();    
    let mut rng = rand::thread_rng();
    let mut hasher = Sha256::new();
    
    let len = 8;
	let mut bigstring : String = (0..len)
            .map(|_| to_valid_char(rng.gen::<u8>() % 62))
            .collect::<String>();
     
    let mut i = 0 as usize;
    loop {
		// Need a block to end borrow of bigstring
		let thex = 
		{
			let hstr = &bigstring[i .. i+len];
			hasher.input_str(hstr);

			// read hash digest
			let mut hex = [0u8; 32];
			hasher.result(&mut hex);
			hasher.reset();
			
			// truncate
			let thex = truncate(&hex);
			
			if bigtable.contains_key(&thex)
			{
				let idx = bigtable[&thex];
				let str1 = &bigstring[idx .. idx+len];
				let str2 = hstr;
				
				if str1 != str2 {
					hasher.input_str(str1);
					let mut h1 = [0u8; 32];
					hasher.result(&mut h1);
					hasher.reset();
					
					hasher.input_str(str2);
					let mut h2 = [0u8; 32];
					hasher.result(&mut h2);
					hasher.reset();
					
					if h1[25] & 0x3 == h2[25] & 0x3	{
						println!("\t-> {:08}", i);
						
						print!("EVO: {} .. {} -> ", &str1, &str2);				
						hexprint(&thex);
						break;
					} else {
						print!("?");
					}
				} else {
					print!("*");
				}
			}
			thex
		};
        
        bigtable.insert(thex, i);
        bigstring.push(to_valid_char(rng.gen::<u8>()));
		
        i += 1;
        if i % 2000000 == 0 {
            println!("\t-> {:08}", i);
        }
    }
}
