//! The authenticated execution dialect is a bounded subset of the frozen
//! language. It has no general native calls, arithmetic/sequence growth,
//! mutation, recursion, comprehensions or recursive container comparisons.
//! This AST guard is applied before evaluation, including unreachable code.
use std::collections::{BTreeMap,BTreeSet};
use enclave_core::{fail,error::EnclaveResult};
use starlark::syntax::ast::{ArgumentP,AssignTargetP,AstExpr,AstLiteral,AstStmt,BinOp,ExprP,StmtP};
use starlark_syntax::lexer::TokenInt;

/// Bound parser recursion before constructing/walking an AST. This lexical
/// screen only adds rejections; parsed node kinds remain authoritative below.
/// Strings/comments do not contribute delimiters or logical statement width.
pub(crate) fn preflight(source:&str)->EnclaveResult<()> {
    let bytes=source.as_bytes();let mut i=0;let mut depth=0usize;
    let mut width=0usize;let mut last=0u8;let mut quote:Option<(u8,bool)>=None;
    let mut at_line_start=true;let mut indent=0usize;let mut indents=vec![0usize];
    while i<bytes.len() {
        let byte=bytes[i];
        if let Some((marker,triple))=quote {
            if byte==b'\\' {i=(i+2).min(bytes.len());continue;}
            if byte==marker && (!triple || bytes.get(i..i+3)==Some(&[marker,marker,marker])) {
                i+=if triple {3} else {1};quote=None;continue;
            }
            i+=1;continue;
        }
        if byte==b'#' {while i<bytes.len() && bytes[i]!=b'\n' {i+=1;}continue;}
        if byte==b'\n' {at_line_start=true;indent=0;}
        else if at_line_start && matches!(byte,b' '|b'\t'|b'\r') {
            indent+=if byte==b'\t' {4} else {1};i+=1;continue;
        } else if at_line_start {
            if depth==0 {
                while indents.last().is_some_and(|previous|*previous>indent) {indents.pop();}
                if indents.last().is_none_or(|previous|*previous<indent) {indents.push(indent);}
                if indents.len()>33 {fail!(E2BIG,"PLAN_LIVE_PARSE_BOUNDS");}
            }
            at_line_start=false;
        }
        if matches!(byte,b'\''|b'"') {
            // F-string placeholders contain parsed code hidden inside string
            // delimiters. They are unsupported by the live AST guard, so
            // reject their prefix before handing contents to the parser.
            let mut prefix=i;
            while prefix>0 && bytes[prefix-1].is_ascii_alphabetic() {prefix-=1;}
            if bytes[prefix..i].iter().any(|byte|matches!(byte,b'f'|b'F')) {
                fail!(EINVAL,"PLAN_LIVE_FSTRING_UNSUPPORTED");
            }
            let triple=bytes.get(i..i+3)==Some(&[byte,byte,byte]);
            quote=Some((byte,triple));i+=if triple {3} else {1};width+=1;last=byte;continue;
        }
        if matches!(byte,b'('|b'['|b'{') {depth+=1;}
        if matches!(byte,b')'|b']'|b'}') {depth=depth.saturating_sub(1);}
        if byte==b'\n' && depth==0 && last!=b'\\' {width=0;last=0;}
        else if !byte.is_ascii_whitespace() {width+=1;last=byte;}
        if depth>32 || width>1024 {fail!(E2BIG,"PLAN_LIVE_PARSE_BOUNDS");}
        i+=1;
    }
    Ok(())
}

pub(crate) fn check(stmt:&AstStmt, bindings:&[(String,super::PlanRef)])->EnclaveResult<()> {
    // Establish structural bounds before collect/scalar recurse over the AST.
    // This pass defers only scalar-type predicates; the full pass below still
    // enforces them after inference, on an already bounded syntax tree.
    Walker {scalars:BTreeSet::new(),shape_only:true,nodes:0,literal_bytes:0}.stmt(stmt,1,0)?;
    let mut definitions=BTreeMap::<String,Vec<&AstExpr>>::new();
    let mut loop_vars=BTreeSet::new();
    collect(stmt,&mut definitions,&mut loop_vars);
    let mut scalars=definitions.keys().cloned().chain(loop_vars).collect::<BTreeSet<_>>();
    for (name,_) in bindings {scalars.remove(name);}
    // Conservative whole-plan inference: any possible container/Ref assignment
    // poisons that name, including forward aliases, branches and loop writes.
    loop {
        let bad=definitions.iter().filter(|(name,values)|scalars.contains(*name)
            && values.iter().any(|value|!scalar(value,&scalars))).map(|(name,_)|name.clone()).collect::<Vec<_>>();
        if bad.is_empty() {break;}
        for name in bad {scalars.remove(&name);}
    }
    Walker {scalars,shape_only:false,nodes:0,literal_bytes:0}.stmt(stmt,1,0)
}
fn collect<'a>(stmt:&'a AstStmt, definitions:&mut BTreeMap<String,Vec<&'a AstExpr>>, loops:&mut BTreeSet<String>) {
    match &stmt.node {
        StmtP::Assign(assign)=>if let AssignTargetP::Identifier(id)=&assign.lhs.node {
            definitions.entry(id.node.ident.clone()).or_default().push(&assign.rhs);
        },
        StmtP::Statements(values)=>for stmt in values {collect(stmt,definitions,loops);},
        StmtP::If(_,body)=>collect(body,definitions,loops),
        StmtP::IfElse(_,bodies)=>{collect(&bodies.0,definitions,loops);collect(&bodies.1,definitions,loops);},
        StmtP::For(loop_)=>{
            if let AssignTargetP::Identifier(id)=&loop_.var.node {loops.insert(id.node.ident.clone());}
            collect(&loop_.body,definitions,loops);
        }
        _=>{}, // Unsupported syntax is rejected exhaustively by Walker.
    }
}
fn scalar(expr:&AstExpr,names:&BTreeSet<String>)->bool {
    match &expr.node {
        ExprP::Literal(_)|ExprP::Not(_)=>true,
        ExprP::Identifier(id)=>matches!(id.node.ident.as_str(),"True"|"False"|"None") || names.contains(&id.node.ident),
        ExprP::Minus(value)|ExprP::Plus(value)=>matches!(value.node,ExprP::Literal(AstLiteral::Int(_))|ExprP::Literal(AstLiteral::Float(_))),
        ExprP::Op(a,BinOp::And|BinOp::Or,b)=>scalar(a,names)&&scalar(b,names),
        ExprP::Op(_,BinOp::Equal|BinOp::NotEqual|BinOp::Less|BinOp::Greater|BinOp::LessOrEqual|BinOp::GreaterOrEqual,_)=>true,
        ExprP::If(parts)=>scalar(&parts.1,names)&&scalar(&parts.2,names),
        _=>false,
    }
}
struct Walker {scalars:BTreeSet<String>,shape_only:bool,nodes:usize,literal_bytes:usize}
impl Walker {
    fn tick(&mut self,multiplier:usize,depth:usize)->EnclaveResult<()> {
        self.nodes=self.nodes.saturating_add(multiplier);
        if depth>32 || self.nodes>8192 {fail!(E2BIG,"PLAN_LIVE_WORK_BOUNDS");} Ok(())
    }
    fn target(&self,target:&starlark::syntax::ast::AstAssignTarget)->EnclaveResult<()> {
        if !matches!(target.node,AssignTargetP::Identifier(_)) {fail!(EINVAL,"PLAN_LIVE_MUTATION_UNSUPPORTED");} Ok(())
    }
    fn stmt(&mut self,stmt:&AstStmt,multiplier:usize,depth:usize)->EnclaveResult<()> {
        self.tick(multiplier,depth)?;
        match &stmt.node {
            StmtP::Break|StmtP::Continue|StmtP::Pass=>Ok(()),
            StmtP::Expression(expr)=>self.expr(expr,multiplier,depth+1),
            StmtP::Assign(assign)=>{
                self.target(&assign.lhs)?;
                if assign.ty.is_some() {fail!(EINVAL,"PLAN_LIVE_SYNTAX_UNSUPPORTED");}
                self.expr(&assign.rhs,multiplier,depth+1)
            }
            StmtP::Statements(values)=>values.iter().try_for_each(|stmt|self.stmt(stmt,multiplier,depth+1)),
            StmtP::If(cond,body)=>{self.expr(cond,multiplier,depth+1)?;self.stmt(body,multiplier,depth+1)},
            StmtP::IfElse(cond,bodies)=>{
                self.expr(cond,multiplier,depth+1)?;
                self.stmt(&bodies.0,multiplier,depth+1)?;self.stmt(&bodies.1,multiplier,depth+1)
            }
            StmtP::For(loop_)=>{
                self.target(&loop_.var)?;
                let bound=range(&loop_.over)?;
                // Range is the sole native call other than the tool builtin;
                // it is admitted only as the exact bounded loop iterable.
                self.stmt(&loop_.body,multiplier.saturating_mul(bound.max(1)),depth+1)
            }
            StmtP::Return(_)|StmtP::AssignModify(..)|StmtP::Def(_)|StmtP::Load(_)=>fail!(EINVAL,"PLAN_LIVE_SYNTAX_UNSUPPORTED"),
        }
    }
    fn expr(&mut self,expr:&AstExpr,multiplier:usize,depth:usize)->EnclaveResult<()> {
        self.tick(multiplier,depth)?;
        match &expr.node {
            ExprP::Literal(literal)=>{
                if let AstLiteral::String(text)=literal {
                    self.literal_bytes=self.literal_bytes.saturating_add(text.node.len().saturating_mul(multiplier));
                    if self.literal_bytes>256*1024 {fail!(E2BIG,"PLAN_LIVE_WORK_BOUNDS");}
                }
                Ok(())
            }
            ExprP::Identifier(_)=>Ok(()),
            ExprP::List(values)|ExprP::Tuple(values)=>values.iter().try_for_each(|value|self.expr(value,multiplier,depth+1)),
            ExprP::Dict(values)=>values.iter().try_for_each(|(key,value)|{
                if !matches!(key.node,ExprP::Literal(AstLiteral::String(_))) {fail!(EINVAL,"PLAN_ARGUMENT_KEY");}
                self.expr(key,multiplier,depth+1)?;self.expr(value,multiplier,depth+1)
            }),
            ExprP::Not(value)=>self.expr(value,multiplier,depth+1),
            ExprP::Minus(value)|ExprP::Plus(value) if self.shape_only || scalar(expr,&self.scalars)=>self.expr(value,multiplier,depth+1),
            ExprP::Op(a,BinOp::And|BinOp::Or,b)=>{self.expr(a,multiplier,depth+1)?;self.expr(b,multiplier,depth+1)},
            ExprP::Op(a,BinOp::Equal|BinOp::NotEqual|BinOp::Less|BinOp::Greater|BinOp::LessOrEqual|BinOp::GreaterOrEqual,b)
                if self.shape_only || (scalar(a,&self.scalars)&&scalar(b,&self.scalars))=>{
                    self.expr(a,multiplier,depth+1)?;self.expr(b,multiplier,depth+1)
                }
            ExprP::If(parts)=>{
                self.expr(&parts.0,multiplier,depth+1)?;self.expr(&parts.1,multiplier,depth+1)?;self.expr(&parts.2,multiplier,depth+1)
            }
            ExprP::Call(function,args) if matches!(&function.node,ExprP::Identifier(id) if id.node.ident=="tool_call")=>{
                for argument in &args.args {
                    let ArgumentP::Positional(value)=&argument.node else {fail!(EINVAL,"PLAN_TOOL_CALL_ARGS");};
                    self.expr(value,multiplier,depth+1)?;
                }
                Ok(())
            }
            ExprP::Call(..)|ExprP::Dot(..)|ExprP::Index(_)|ExprP::Index2(_)|ExprP::Slice(..)|ExprP::Lambda(_)
                |ExprP::FString(_)|ExprP::ListComprehension(..)|ExprP::DictComprehension(..)|ExprP::Op(..)
                |ExprP::Minus(_)|ExprP::Plus(_)|ExprP::BitNot(_)=>fail!(EINVAL,"PLAN_LIVE_SYNTAX_UNSUPPORTED"),
        }
    }
}
fn range(over:&AstExpr)->EnclaveResult<usize> {
    if let ExprP::Call(function,args)=&over.node {
        if matches!(&function.node,ExprP::Identifier(id) if id.node.ident=="range") {
            if let [argument]=args.args.as_slice() {
                if let ArgumentP::Positional(expr)=&argument.node {
                    if let ExprP::Literal(AstLiteral::Int(value))=&expr.node {
                        if let TokenInt::I32(n)=&value.node {
                            if (0..=16).contains(n) {return Ok(*n as usize);}
                        }
                    }
                }
            }
        }
    }
    fail!(EINVAL,"PLAN_LIVE_LOOP_BOUND")
}
