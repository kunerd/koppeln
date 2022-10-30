use nom::{
    bytes::complete::{is_not, tag, take_till, take_until},
    character::complete::{alpha1, multispace0},
    combinator::opt,
    error::ParseError,
    multi::separated_list0,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};

use std::net::Ipv4Addr;

fn ws<'a, F: 'a, O, E: ParseError<&'a str>>(
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: FnMut(&'a str) -> IResult<&'a str, O, E>,
{
    delimited(multispace0, inner, multispace0)
}

fn opcode(input: &str) -> IResult<&str, &str> {
    header_field("opcode")(input)
}

fn rcode(input: &str) -> IResult<&str, &str> {
    header_field("rcode")(input)
}

fn flags(input: &str) -> IResult<&str, Vec<String>> {
    let (input, _) = take_until("flags:")(input)?;
    let (input, r) = preceded(tag("flags:"), take_till(|c| c == ';'))(input)?;

    let (_, list) = preceded(multispace0, separated_list0(tag(" "), alpha1))(r)?;

    let (input, _) = terminated(tag(";"), multispace0)(input)?;
    Ok((input, list.iter().map(|s| s.to_string()).collect()))
}

fn header_field(field_name: &str) -> impl FnOnce(&str) -> IResult<&str, &str> {
    let field_tag = format!("{}:", field_name);
    move |input| {
        delimited(
            tag(field_tag.as_str()),
            ws(alpha1),
            terminated(tag(","), multispace0),
        )(input)
    }
}

fn find_answer_section(input: &str) -> IResult<&str, &str> {
    let (input, _) = take_until(";; ANSWER SECTION:")(input)?;
    tag(";; ANSWER SECTION:\n")(input)
}

fn parse_answer_section(input: &str) -> IResult<&str, DrillAnswer> {
    let (input, answer) = separated_pair(
        is_not("\t"),
        tuple((
            tag("\t"),
            nom::character::complete::digit1,
            tag("\t"),
            alpha1,
            tag("\t"),
            alpha1,
            tag("\t"),
        )),
        is_not("\n"),
    )(input)?;

    Ok((
        input,
        DrillAnswer {
            domain_name: answer.0.to_string(),
            ip: answer.1.parse().unwrap(),
        },
    ))
}

#[derive(Debug)]
pub struct DrillOutput {
    pub opcode: String,
    pub rcode: String,
    pub flags: Vec<String>,
    pub answer: Option<DrillAnswer>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DrillAnswer {
    pub domain_name: String,
    pub ip: Ipv4Addr,
}

pub fn parse_answer(input: &str) -> IResult<&str, DrillAnswer> {
    let (input, _) = find_answer_section(input)?;

    parse_answer_section(input)
}

pub fn parse_drill_output(input: &str) -> IResult<&str, DrillOutput> {
    let (input, _) = find_header(input)?;
    let (input, (opcode, rcode, flags)) = tuple((opcode, rcode, flags))(input)?;

    let (input, _) = find_answer_section(input)?;
    let (input, answer) = opt(parse_answer_section)(input)?;

    let drill_output = DrillOutput {
        opcode: opcode.to_string(),
        rcode: rcode.to_string(),
        answer,
        flags,
    };

    Ok((input, drill_output))
}

pub fn find_header(input: &str) -> IResult<&str, &str> {
    let (input, _) = tag(";;")(input)?;
    delimited(tag(" "), tag("->>HEADER<<-"), tag(" "))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_find_header() {
        let input = ";; ->>HEADER<<- content";

        assert_eq!(find_header(input), Ok(("content", "->>HEADER<<-")));
    }

    #[test]
    fn test_parse_opcode() {
        let input = "opcode: QUERY, rcode: NXDOMAIN";

        assert_eq!(opcode(input), Ok(("rcode: NXDOMAIN", "QUERY")));
    }

    #[test]
    fn test_parse_rcode() {
        let input = "rcode: NXDOMAIN, id: 12345";

        assert_eq!(rcode(input), Ok(("id: 12345", "NXDOMAIN")));
    }

    #[test]
    fn test_parse_flags() {
        let input = "flags: qr rd ra ; QUERY: 1";

        assert_eq!(
            flags(input),
            Ok((
                "QUERY: 1",
                vec!["qr".to_string(), "rd".to_string(), "ra".to_string()]
            ))
        );
    }

    #[test]
    fn test_find_answer_section() {
        //let output = r"
        //;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 5860
        //;; flags: qr aa rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        //;; QUESTION SECTION:
        //;; koppeln.lxd.	IN	A
        //
        //;; ANSWER SECTION:
        //koppeln.lxd.	0	IN	A	10.228.250.78
        //
        //;; AUTHORITY SECTION:
        //
        //;; ADDITIONAL SECTION:
        //
        //;; Query time: 0 msec
        //;; SERVER: 10.228.250.1
        //;; WHEN: Thu Mar 11 17:01:16 2021
        //;; MSG SIZE  rcvd: 45
        //";

        let stdout = indoc!(
            r#"
            something
            ;; ANSWER SECTION:
            koppeln.lxd.	0	IN	A	10.228.250.78
        "#
        );

        let result = find_answer_section(stdout);

        assert_eq!(
            result,
            Ok((
                indoc!(
                    r#"
                    koppeln.lxd.	0	IN	A	10.228.250.78
                "#
                ),
                ";; ANSWER SECTION:\n"
            ))
        );
    }

    #[test]
    fn test_parse_answer_section() {
        let input = "koppeln.lxd.	0	IN	A	10.228.250.78";
        let result = parse_answer_section(input);

        assert_eq!(
            result,
            Ok((
                "",
                DrillAnswer {
                    domain_name: "koppeln.lxd.".to_string(),
                    ip: Ipv4Addr::new(10, 228, 250, 78)
                }
            ))
        );
    }

    #[test]
    fn test_parse_drill_output_without_answer() {
        let drill_stdout = indoc!(
            r"
            ;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 5860
            ;; flags: qr aa rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;; koppeln.lxd.	IN	A
            
            ;; ANSWER SECTION:
            
            ;; AUTHORITY SECTION:
            
            ;; ADDITIONAL SECTION:
            
            ;; Query time: 0 msec
            ;; SERVER: 10.228.250.1
            ;; WHEN: Thu Mar 11 17:01:16 2021
            ;; MSG SIZE  rcvd: 45
        "
        );

        let (_, drill_output) = parse_drill_output(drill_stdout).unwrap();
        assert_eq!(drill_output.opcode, "QUERY");
        assert_eq!(drill_output.rcode, "NOERROR");
        assert_eq!(drill_output.flags, vec!["qr", "aa", "rd", "ra"]);
        assert_eq!(drill_output.answer, None);
    }

    #[test]
    fn test_parse_drill_output() {
        let drill_stdout = indoc!(
            r"
            ;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 5860
            ;; flags: qr aa rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;; koppeln.lxd.	IN	A
            
            ;; ANSWER SECTION:
            .	15	IN	A	1.2.3.4
            
            ;; AUTHORITY SECTION:
            
            ;; ADDITIONAL SECTION:
            
            ;; Query time: 0 msec
            ;; SERVER: 10.228.250.1
            ;; WHEN: Thu Mar 11 17:01:16 2021
            ;; MSG SIZE  rcvd: 45
        "
        );

        let (_, drill_output) = parse_drill_output(drill_stdout).unwrap();
        assert_eq!(drill_output.opcode, "QUERY");
        assert_eq!(drill_output.rcode, "NOERROR");
        assert_eq!(drill_output.flags, vec!["qr", "aa", "rd", "ra"]);
        assert_eq!(
            drill_output.answer,
            Some(DrillAnswer {
                domain_name: ".".to_string(),
                ip: Ipv4Addr::new(1, 2, 3, 4),
            })
        );
    }
}
