use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    Argon2,
};
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read};

const PASSWORD_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const MAGIC_XOR_KEY: u8 = 0xA5;

/// 简单的“魔改”混淆/反混淆函数
/// 算法: output[i] = input[i] ^ MAGIC_KEY ^ index
/// 这是一个对称操作，加密和解密调用同一个函数即可
fn transform_password_block(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ MAGIC_XOR_KEY ^ (i as u8))
        .collect()
}

/// 使用 Argon2id 从密码和盐派生出 32 字节的 AES 密钥
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], Box<dyn Error>> {
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; KEY_LEN];
    
    argon2.hash_password_into(password, salt, &mut output_key_material)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(output_key_material)
}

pub fn decrypt_file(
    input_path: &str, 
    output_path: &str
) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1. 读取文件
    let mut file = File::open(input_path)?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content)?;

    // 校验最小长度
    let min_len = PASSWORD_LEN + SALT_LEN + NONCE_LEN;
    if file_content.len() < min_len {
        return Err("File is too short/corrupted".into());
    }

    // 2. 解析文件结构
    // [0..16] 是混淆的密码
    let obfuscated_pw = &file_content[0..PASSWORD_LEN];
    // [16..32] 是盐
    let salt = &file_content[PASSWORD_LEN..PASSWORD_LEN + SALT_LEN];
    // [32..44] 是 Nonce
    let nonce_bytes = &file_content[PASSWORD_LEN + SALT_LEN..min_len];
    // [44..] 是密文
    let ciphertext = &file_content[min_len..];

    // 3. “魔改”还原密码
    // 这是一个自包含的过程，不需要用户交互
    let recovered_password_vec = transform_password_block(obfuscated_pw);
    let recovered_password = &recovered_password_vec;

    // 4. 重新派生密钥
    let key_bytes = derive_key(recovered_password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // 5. 解密
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Error")?;

    // 6. 保存
    fs::write(output_path, &plaintext)?;
    Ok(plaintext)
}