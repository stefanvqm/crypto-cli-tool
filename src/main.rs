
// Import necessary standard library modules
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use std::borrow::Borrow;

// Import cryptographic functionality
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use generic_array::GenericArray;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

// Constant to define a specific exit code
const EXITCODE: i32 = 0x0100;

// Enums to define types of paths, keys, and operations
#[derive(PartialEq, Debug)]
enum PathType {
    Directory = 1,
    File = 2,
    None = 3,
}

#[derive(PartialEq, Debug)]
enum KeyType {
    String = 1,
    File = 2,
    None = 3,
}

#[derive(PartialEq, Debug)]
enum OperationType {
    Encryption = 1,
    Decryption = 2,
    None = 3,
}

// Implement `Default` for enums to provide a default value
impl Default for PathType {
    fn default() -> Self { PathType::None }
}

impl Default for KeyType {
    fn default() -> Self { KeyType::None }
}

impl Default for OperationType {
    fn default() -> Self { OperationType::None }
}

// Struct to store the result of argument validation
#[derive(Default)]
struct ValidationResult {
    status: bool,
    message: String,
    operation: OperationType,
    path: (PathType, usize),
    key: (KeyType, usize),
}

fn main() {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();
    
    // Validate arguments and determine operation
    let result: ValidationResult = validate_arguments(&args);
    
    // If validation fails, print the error message and exit
    if !result.status {
        println!("{:?}", result.message);
        process::exit(EXITCODE);
    }

    // Process the arguments based on the validation result
    process_arguments(&args, &result).unwrap_or_else(|e| {
        eprintln!("Error processing arguments: {}", e);
        process::exit(EXITCODE);
    });
}

// Function to display help text (manpage)
fn manpage() {
    println!("\nManpage coming soon!\n");
    process::exit(EXITCODE);
}

// Function to validate command-line arguments
fn validate_arguments(args: &Vec<String>) -> ValidationResult {
    // Helper function to find an argument in the command-line args
    let find_in_args = |to_find: &str| -> usize {
        args.iter().enumerate().find(|&(_, value)| value == to_find)
            .map_or(0, |(index, _)| index)
    };

    // Determine if the path argument points to a file or directory
    let path_type = | index: usize | -> PathType {
        if index >= args.len() {
            return PathType::None;
        } 
        
        let path: &Path = Path::new(&args[index + 1]);
        
        if !path.exists() {
            return PathType::None;
        }
        
        let mut dir_or_file: PathType = PathType::None;
        
        if path.is_file() {
            dir_or_file = PathType::File;
        } else if path.is_dir() {
            dir_or_file = PathType::Directory;
        }

        return dir_or_file;
    };


    // Determine if the key argument is a string or points to a file
    let key_type = | index: usize | -> KeyType {
        if index >= args.len() {
            return KeyType::None;
        } 

        let path: &Path = Path::new(&args[index + 1]);

        let mut string_or_key: KeyType = KeyType::None;

        if path.exists() {
            if path.is_file() {
                string_or_key = KeyType::File;
            } else {
                string_or_key = KeyType::None;
            }
        } else {
            string_or_key = KeyType::String;
        }

        return string_or_key;
    };
    
    // Check for help argument
    if find_in_args("-h") != 0 {
        manpage();
    }

    // Initialize variables to store path and key data
    let mut path_data: (PathType, usize) = Default::default();
    let mut key_data: (KeyType, usize) = Default::default();
    let mut operation: OperationType = Default::default();

    let failed_validation_result = |additional_message: &str| -> ValidationResult {
        ValidationResult {
            status: false, 
            message: format!("Mismatched arguments. {}", additional_message),
            ..Default::default()
        }
    };

    // Iterate over arguments to determine operation, path, and key types
    for (index, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "-e" => {                
                if find_in_args(String::from("-d").borrow()) != 0 {
                    return failed_validation_result("1");
                } else {
                    operation = OperationType::Encryption;
                };
            },
            "-d" => {
                if find_in_args(String::from("-e").borrow()) != 0 {
                    return failed_validation_result("2");
                } else {
                    operation = OperationType::Decryption;
                };
            },
            "-p" => {
                path_data = (path_type(index), index);

                if path_data.0 == PathType::None {
                    return failed_validation_result("3");
                } else {
                    path_data.1 += 1
                }
            },
            "-k" => {
                key_data = (key_type(index), index);

                if key_data.0 == KeyType::None {
                    return failed_validation_result("4");
                } else {
                    key_data.1 += 1
                }
            },
            _ =>  ()
        }
    }

    // Validate the determined operation, path, and key types
    if operation == OperationType::None || path_data.0 == PathType::None || key_data.0 == KeyType::None {
        return failed_validation_result("5");
    }

    ValidationResult {
        status: true, 
        message: String::from("Arguments accepted."),
        operation,
        path: path_data,
        key: key_data,
    }
}

// Function to read the content of a file as bytes
fn read_file_as_bytes(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

fn process_arguments(args: &Vec<String>, result: &ValidationResult) -> io::Result<()> {
    let mut key_bytes: Vec<u8> = Vec::new();

    // Determine how to handle the key based on whether it's specified as a file or a direct string
    if result.key.0 == KeyType::File {
        // If the key is specified as a file, read its contents as bytes
        match read_file_as_bytes(&args[result.key.1]) {
            Ok(bytes) => {
                key_bytes = bytes; 
            },
            Err(e) => {
                println!("Failed to read key file: {}", e);
                process::exit(EXITCODE);
            } 
        };
    } else {
        // If the key is specified as a string, directly convert it to bytes
        key_bytes = args[result.key.1].as_bytes().to_vec();
    }
    
    // Convert the key bytes vector into a byte slice for use in encryption/decryption functions
    let key: &[u8] = &key_bytes;

    // Process based on the operation type: Encryption or Decryption
    match result.operation {
        OperationType::Encryption => {
            match result.path.0 {
                PathType::Directory => {
                    println!("Directory encryption is not supported in this example.");
                    process::exit(EXITCODE);
                },
                PathType::File => {
                    // Encrypt the specified file
                    encrypt_file(&args[result.path.1], &key)
                }
                _ => {
                    println!("Invalid path type.");
                    process::exit(EXITCODE);
                }
            }
        },
        OperationType::Decryption => {
            match result.path.0 {
                PathType::Directory => {
                    println!("Directory decryption is not supported in this example.");
                    process::exit(EXITCODE);
                },
                PathType::File => {
                    // Encrypt the specified file
                    decrypt_file(&args[result.path.1], &key)
                }
                _ => {
                    println!("Invalid path type.");
                    process::exit(EXITCODE);
                }
            }
        },
        _ => {
            // If the operation type is not recognized, exit with an error
            println!("Invalid operation type.");
            Err(io::Error::new(io::ErrorKind::Other, "Invalid operation"))
        },
    }
}

// Function to derive a key using HKDF
fn derive_key(input_key: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, input_key);
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm).expect("HKDF should not fail with valid parameters");
    okm
}

// Function to encrypt a file
fn encrypt_file(path: &str, input_key: &[u8]) -> io::Result<()> {
    // Derive a 32-byte key using HKDF
    let key = derive_key(input_key);

    // Open the file and read its contents
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Initialize the cipher with the key
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

    // Generate a random nonce for AES-GCM
    let nonce = rand::thread_rng().gen::<[u8; 12]>();

    // Encrypt the contents
    let encrypted_data = cipher.encrypt(GenericArray::from_slice(&nonce), contents.as_ref())
        .expect("encryption failure");

    // Write the nonce and encrypted data to a new file
    let mut output_file = File::create(format!("{}.enc", path))?;
    // It's important to store the nonce with the encrypted data; prepend or append it to the file
    output_file.write_all(&nonce)?;
    output_file.write_all(&encrypted_data)?;

    Ok(())
}

// Function to decrypt a file
fn decrypt_file(path: &str, input_key: &[u8]) -> io::Result<()> {
    // Derive the 32-byte key using the same HKDF method
    let key = derive_key(input_key);

    // Open the encrypted file and read its contents
    let mut file = File::open(path)?;
    let mut encrypted_contents = Vec::new();
    file.read_to_end(&mut encrypted_contents)?;

    // Separate the nonce from the encrypted data
    // Assuming the nonce is the first 12 bytes of the file
    let (nonce, encrypted_data) = encrypted_contents.split_at(12);
    
    // Initialize the cipher with the derived key
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

    // Decrypt the contents using the nonce and encrypted data
    let decrypted_data = cipher.decrypt(GenericArray::from_slice(nonce), encrypted_data)
        .expect("decryption failure");

    // Write the decrypted data to a new file, or overwrite the encrypted one
    // The file name is derived by removing ".enc", handling errors as needed
    let output_path = path.trim_end_matches(".enc");
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}