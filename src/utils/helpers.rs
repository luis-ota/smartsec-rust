pub fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut result = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for word in text.split_whitespace() {
        let word_len = unicode_width::UnicodeWidthStr::width(word);
        if current_len > 0 && current_len + 1 + word_len > max_width {
            result.push(current.trim_end().to_string());
            current = word.to_string();
            current_len = word_len;
        } else if current_len > 0 {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + word_len;
        } else {
            current = word.to_string();
            current_len = word_len;
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}
