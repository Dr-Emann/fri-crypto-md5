extern crate crypto;
extern crate rand;
extern crate scoped_threadpool;
extern crate num_cpus;

use scoped_threadpool::Pool;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;
use rand::SeedableRng;
use rand::XorShiftRng;

use std::fmt::Write;
use std::fmt;
use std::mem;
use std::str;
use std::collections::HashMap;
use std::sync::mpsc::sync_channel;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::*;

const DATA_LEN: usize = 8;
const HASH_LEN: usize = 6;

struct HexDisplay<'a>(&'a [u8]);

impl<'a> fmt::Display for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in self.0 {
            try!(write!(f, "{:02X}", i));
        }
        Ok(())
    }
}

fn shift_left(data: &mut [u8]) {
    for i in 0..(data.len() - 1) {
        data[i] = data[i+1];
    }
}

fn truncate_hash(hash: &[u8]) -> [u8; HASH_LEN] {
    [hash[26], hash[27], hash[28], hash[29], hash[30], hash[31]]
}

fn oneshot_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let mut full_hash = [0u8; 32]; // could use mem::uninitialized
    hasher.result(&mut full_hash);
    full_hash
}

struct DataGenerator {
    initial_seed: [u32; 4],
    data: [u8; DATA_LEN],
    rng: XorShiftRng,
    i: usize,
}

impl DataGenerator {
    fn new(initial_seed: [u32; 4], i: usize) -> DataGenerator {
        let mut result = DataGenerator {
            initial_seed: initial_seed,
            data: [0; DATA_LEN],
            rng: XorShiftRng::new_unseeded(),
            i: 0,
        };
        result.reseed(i);
        result
    }

    fn set_i(&mut self, i: usize) {
        if self.i + 1 == i {
            shift_left(&mut self.data);
            *self.data.last_mut().unwrap() = self.rng.gen_ascii_chars().next().unwrap() as u8;
        }
        else if self.i != self.i {
            self.reseed(i);
        }
    }

    fn data(&mut self, i: usize) -> [u8; DATA_LEN] {
        self.set_i(i);
        self.next().unwrap()
    }

    fn reseed(&mut self, i: usize) {
        let last_reseed = i / 1024;
        let seed = {
            let mut seed = self.initial_seed;
            let last_reseed = last_reseed as u64;
            seed[2] = seed[2].wrapping_add((last_reseed >> 32) as u32);
            seed[3] = seed[3].wrapping_add(last_reseed as u32);
            seed
        };
        self.rng.reseed(seed);
        for _ in self.rng.gen_ascii_chars().take(i % 1024) {
            // Just draining from rng
        }
        for (x, y) in self.data.iter_mut().zip(self.rng.gen_ascii_chars()) {
            *x = y as u8;
        }
    }
}

impl Iterator for DataGenerator {
    type Item = [u8; DATA_LEN];
    
    fn next(&mut self) -> Option<[u8; DATA_LEN]> {
        let result = self.data;
        let i = self.i + 1;
        self.set_i(i);
        Some(result)
    }
}


enum Message {
    Progress(usize),
    Data(Vec<([u8; HASH_LEN], usize)>),
}

fn main() {
    let mut bigtable = HashMap::<[u8; HASH_LEN], usize>::new();
    let mut rng = rand::weak_rng();
    let initial_seed = [rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32()];
    let count = AtomicUsize::new(0);
    let (tx, rx) = sync_channel(32);
    let thread_count = num_cpus::get();

    let mut pool = Pool::new(thread_count as u32);
    pool.scoped(|scope| {
        let count = &count;
        let size = usize::max_value() / thread_count;
        for thread in 0..thread_count {
            let tx = tx.clone();
            scope.execute(move || {
                let mut generator = DataGenerator::new(initial_seed, size * thread);
                let mut map = Vec::with_capacity(1024);
                for i in 0..size {
                    let current_count = count.fetch_add(1, Relaxed);
                    if current_count % 2_000_000 == 0 {
                        if tx.send(Message::Progress(current_count)).is_err() {
                            break;
                        }
                    }
                    if map.len() == 1024 {
                        if tx.send(Message::Data(mem::replace(&mut map, Vec::with_capacity(1024)))).is_err() {
                            break;
                        }
                    }
                    let i = i + size * thread;
                    
                    let hash = oneshot_hash(&generator.next().unwrap());
                    let truncated = truncate_hash(&hash);
                    map.push((truncated, i));
                }
            });
        }
        drop(tx);
        let mut generator = DataGenerator::new(initial_seed, 0);
        'outer: for item in rx.iter() {
            match item {
                Message::Progress(i) => { println!("\t-> {:08}", i); },
                Message::Data(v) => {
                    for (hash, i) in v {
                        if let Some(old_i) = bigtable.insert(hash, i) {
                            let old_str = generator.data(old_i);
                            let old_hash = oneshot_hash(&old_str);
                            let new_str = generator.data(i);
                            let new_hash = oneshot_hash(&new_str);
                            if old_str != new_str {
                                if old_hash[25] & 0x3 == new_hash[25] & 0x3 {
                                    println!("\t-> {:08}", count.load(Relaxed));
                                    println!("EVO: {} .. {} -> {}", 
                                             str::from_utf8(&old_str).unwrap(), str::from_utf8(&new_str).unwrap(),
                                             HexDisplay(&hash));
                                    break 'outer;
                                }
                                else {
                                    println!("?");
                                }
                            }
                            else {
                                print!("*");
                            }
                        }
                    }
                }
            }
        }
        drop(rx);
    });
}
