//! Scripted protocol fixture. This is NOT an LLM/provider/AI proof.
use std::io::Read;
fn main() {
    let mut input=String::new();
    std::io::stdin().take(8193).read_to_string(&mut input).unwrap();
    assert!(input.len()<=8192);
    let (name,args)=if input.contains("undeclared") { ("unselected",r#"{\"text\":\"celln\"}"#) }
        else if input.contains("invalid-arguments") { ("uppercase",r#"{\"text\":7}"#) }
        else if input.contains("bad-result") { ("uppercase",r#"{\"text\":\"bad-result\"}"#) }
        else if input.contains("sleep") { ("uppercase",r#"{\"text\":\"sleep\"}"#) }
        else if input.contains("flood") { ("uppercase",r#"{\"text\":\"flood\"}"#) }
        else { match input.matches("\"role\":\"tool\"").count() {
            0 => ("uppercase",r#"{\"text\":\"celln\"}"#),
            1 => ("length",r#"{\"text\":\"CELLN\"}"#),
            _ => { println!(r#"{{"choices":[{{"message":{{"role":"assistant","content":"CELLN has length 5"}}}}]}}"#); return; }
        }};
    println!(r#"{{"choices":[{{"message":{{"role":"assistant","content":null,"tool_calls":[{{"id":"call-{name}","type":"function","function":{{"name":"{name}","arguments":"{args}"}}}}]}}}}]}}"#);
}
