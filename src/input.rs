use crate::Result;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use tracing::{info, warn};

/// A Shard is a input file split into size `n` chunks
#[derive(Debug)]
pub struct Input {
    lines: Vec<String>,
    batches: Vec<Vec<String>>,
}

impl Input {
    /// Builds a new `Input` reading the contents of stdin or a file into `Input.lines`
    pub fn new(path: Option<&str>) -> Self {
        let lines = Self::read_input(path).expect("unable to read input");
        Self {
            lines,
            batches: Vec::new(),
        }
    }

    /// Reads input from stdin or a file
    fn read_input(path: Option<&str>) -> Result<Vec<String>> {
        let mut contents = Vec::new();
        let reader: Box<dyn BufRead> = match path {
            Some(filepath) => {
                Box::new(BufReader::new(File::open(filepath).map_err(|e| {
                    format!("tried to read filepath {} got {}", &filepath, e)
                })?))
            }
            None => Box::new(BufReader::new(io::stdin())),
        };

        for line in reader.lines() {
            contents.push(line?)
        }

        Ok(contents)
    }

    /// Returns the total contents of the input
    pub fn lines(self) -> Vec<String> {
        self.lines
    }

    /// builds a set of batches out of the input
    pub fn build_batches(&mut self, batch_size: usize) -> &mut Self {
        //TODO: check that the batch_size is not greater than the input size.
        info!("building batches of size {}", batch_size);

        let bsize = self.lines.len() / batch_size;
        let batch_iter = self.lines.chunks_exact(bsize);
        let remainder = batch_iter.remainder();
        self.batches
            .extend(batch_iter.map(|b| b.to_vec()).collect::<Vec<Vec<String>>>());

        let last = self.batches.len() - 1;
        if !remainder.is_empty() {
            self.batches[last].extend_from_slice(&remainder);
        }

        info!("total number of batches {}", &self.batches.len());
        self
    }

    /// Returns a copy of the particular batch or `None` if the `batch_idx` is out of bounds.
    pub fn batch(&self, batch_idx: usize) -> Option<Vec<String>> {
        if !batch_idx.gt(&self.batches.len()) {
            Some(self.batches[batch_idx].to_vec())
        } else {
            warn!("batch index out of bounds");
            None
        }
    }
}
