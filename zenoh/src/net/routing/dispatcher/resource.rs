//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use std::{
    any::Any,
    collections::HashMap,
    convert::TryInto,
    hash::{Hash, Hasher},
    sync::{Arc, Weak},
    fmt
};

use tokio_util::context;
use zenoh_config::WhatAmI;
use zenoh_protocol::{
    core::{key_expr::keyexpr, ExprId, WireExpr},
    network::{
        declare::{ext, queryable::ext::QueryableInfoType, Declare, DeclareBody, DeclareKeyExpr},
        interest::InterestId,
        Mapping, RequestId,
    },
};
use zenoh_sync::get_mut_unchecked;

use super::{
    face::FaceState,
    pubsub::SubscriberInfo,
    tables::{Tables, TablesLock},
};
use crate::net::routing::{dispatcher::face::Face, RoutingContext};

use derive_more::Debug;

pub(crate) type NodeId = u16;

pub(crate) type Direction = (Arc<FaceState>, WireExpr<'static>, NodeId);
pub(crate) type Route = HashMap<usize, Direction>;

pub(crate) type QueryRoute = HashMap<usize, (Direction, RequestId)>;
#[derive(Debug)]
pub(crate) struct QueryTargetQabl {
    pub(crate) direction: Direction,
    pub(crate) info: Option<QueryableInfoType>,
}
pub(crate) type QueryTargetQablSet = Vec<QueryTargetQabl>;

#[derive(Debug)]
pub(crate) struct SessionContext {
    pub(crate) face: Arc<FaceState>,
    pub(crate) local_expr_id: Option<ExprId>,
    pub(crate) remote_expr_id: Option<ExprId>,
    pub(crate) subs: Option<SubscriberInfo>,
    pub(crate) qabl: Option<QueryableInfoType>,
    pub(crate) token: bool,
    pub(crate) in_interceptor_cache: Option<Box<dyn Any + Send + Sync>>,
    pub(crate) e_interceptor_cache: Option<Box<dyn Any + Send + Sync>>,
}

impl SessionContext {
    pub(crate) fn new(face: Arc<FaceState>) -> Self {
        Self {
            face,
            local_expr_id: None,
            remote_expr_id: None,
            subs: None,
            qabl: None,
            token: false,
            in_interceptor_cache: None,
            e_interceptor_cache: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct RoutesIndexes {
    pub(crate) routers: Vec<NodeId>,
    pub(crate) peers: Vec<NodeId>,
    pub(crate) clients: Vec<NodeId>,
}

#[derive(Default, Debug)]
pub(crate) struct DataRoutes {
    pub(crate) routers: Vec<Arc<Route>>,
    pub(crate) peers: Vec<Arc<Route>>,
    pub(crate) clients: Vec<Arc<Route>>,
}

impl DataRoutes {
    #[inline]
    pub(crate) fn get_route(&self, whatami: WhatAmI, context: NodeId) -> Option<Arc<Route>> {
        match whatami {
            WhatAmI::Router => (self.routers.len() > context as usize)
                .then(|| self.routers[context as usize].clone()),
            WhatAmI::Peer => {
                (self.peers.len() > context as usize).then(|| self.peers[context as usize].clone())
            }
            WhatAmI::Client => (self.clients.len() > context as usize)
                .then(|| self.clients[context as usize].clone()),
        }
    }
}

#[derive(Default, Debug)]
pub(crate) struct QueryRoutes {
    pub(crate) routers: Vec<Arc<QueryTargetQablSet>>,
    pub(crate) peers: Vec<Arc<QueryTargetQablSet>>,
    pub(crate) clients: Vec<Arc<QueryTargetQablSet>>,
}

impl QueryRoutes {
    #[inline]
    pub(crate) fn get_route(
        &self,
        whatami: WhatAmI,
        context: NodeId,
    ) -> Option<Arc<QueryTargetQablSet>> {
        match whatami {
            WhatAmI::Router => (self.routers.len() > context as usize)
                .then(|| self.routers[context as usize].clone()),
            WhatAmI::Peer => {
                (self.peers.len() > context as usize).then(|| self.peers[context as usize].clone())
            }
            WhatAmI::Client => (self.clients.len() > context as usize)
                .then(|| self.clients[context as usize].clone()),
        }
    }
}

// #[derive(Debug)]
pub(crate) struct ResourceContext {
    pub(crate) matches: Vec<Weak<Resource>>,
    pub(crate) hat: Box<dyn Any + Send + Sync>,
    pub(crate) valid_data_routes: bool,
    pub(crate) data_routes: DataRoutes,
    pub(crate) valid_query_routes: bool,
    pub(crate) query_routes: QueryRoutes,
}

impl fmt::Debug for ResourceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut resource_context = f.debug_struct("ResourceContext");
        resource_context.field("matches", &self.matches.iter().filter_map(|resource|resource.upgrade()).map(|resource|resource.format_for_no_recursive()).collect::<Vec<String>>());
        // resource_context.field("matches", &self.matches.iter().filter_map(|resource| {
        //     resource.upgrade().map(|res| res.format_excluding_matches())
        // }).collect::<Vec<String>>());
        resource_context.field(
            "data_routes.routers",
            &format_args!(
                "\n[{}]",
                self.data_routes
                    .routers
                    .iter()
                    .map(|route_map| {
                        let inner = route_map
                            .iter()
                            .map(|(k, v)| format!("    {:?}: {:?}", k, v))
                            .collect::<Vec<_>>()
                            .join(",\n");
                        format!("{{{}\n }}", inner)
                    })
                    .collect::<Vec<_>>()
                    .join(",\n")
            ),
        );
        resource_context.field(
            "data_routes.peers",
            &format_args!(
                "\n[{}]",
                self.data_routes
                    .peers
                    .iter()
                    .map(|route_map| {
                        let inner = route_map
                            .iter()
                            .map(|(k, v)| format!("    {:?}: {:?}", k, v))
                            .collect::<Vec<_>>()
                            .join(",\n");
                        format!("{{{}\n }}", inner)
                    })
                    .collect::<Vec<_>>()
                    .join(",\n")
            ),
        );
        resource_context.field(
            "data_routes.clients",
            &format_args!(
                "\n[{}]",
                self.data_routes
                    .clients
                    .iter()
                    .map(|route_map| {
                        let inner = route_map
                            .iter()
                            .map(|(k, v)| format!("    {:?}: {:?}", k, v))
                            .collect::<Vec<_>>()
                            .join(",\n");
                        format!("{{{}\n }}", inner)
                    })
                    .collect::<Vec<_>>()
                    .join(",\n")
            ),
        );
        resource_context.finish()
    }
}


impl ResourceContext {
    fn new(hat: Box<dyn Any + Send + Sync>) -> ResourceContext {
        ResourceContext {
            matches: Vec::new(),
            hat,
            valid_data_routes: false,
            data_routes: DataRoutes::default(),
            valid_query_routes: false,
            query_routes: QueryRoutes::default(),
        }
    }

    pub(crate) fn update_data_routes(&mut self, data_routes: DataRoutes) {
        self.valid_data_routes = true;
        self.data_routes = data_routes;
    }

    pub(crate) fn disable_data_routes(&mut self) {
        self.valid_data_routes = false;
    }

    pub(crate) fn update_query_routes(&mut self, query_routes: QueryRoutes) {
        self.valid_query_routes = true;
        self.query_routes = query_routes
    }

    pub(crate) fn disable_query_routes(&mut self) {
        self.valid_query_routes = false;
    }
}

pub struct Resource {
    pub(crate) parent: Option<Arc<Resource>>,
    pub(crate) suffix: String,
    pub(crate) nonwild_prefix: Option<(Arc<Resource>, String)>,
    pub(crate) children: HashMap<String, Arc<Resource>>,
    pub(crate) context: Option<ResourceContext>,
    pub(crate) session_ctxs: HashMap<usize, Arc<SessionContext>>,
}

// impl fmt::Debug for Resource {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         writeln!(f, "Resource {{")?;
//         writeln!(f, "    suffix: \"{}\",", self.suffix)?;

//         if let Some(resource_context) = &self.context {
//             writeln!(f, "    data_routes.routers: [")?;
//             for router in &resource_context.data_routes.routers {
//                 writeln!(f, "        {:?},", router)?;
//             }
//             writeln!(f, "    ],")?;

//             writeln!(f, "    data_routes.peers: [")?;
//             for peer in &resource_context.data_routes.peers {
//                 writeln!(f, "        {:?},", peer)?;
//             }
//             writeln!(f, "    ],")?;

//             writeln!(f, "    data_routes.clients: [")?;
//             for client in &resource_context.data_routes.clients {
//                 writeln!(f, "        {:?},", client)?;
//             }
//             writeln!(f, "    ],")?;
//         }

//         writeln!(f, "    children: {:?},", self.children)?;
//         writeln!(f, "}}")
//     }
// }

impl fmt::Debug for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut resource = f.debug_struct("Resource");
        
        resource.field("suffix", &self.suffix);
        
        if let Some(resource_context) = &self.context {
            resource.field("resource_context", resource_context);
            // resource.field("matches", &resource_context.matches);
            // resource.field(
            //     "data_routes.routers",
            //     &format_args!(
            //         "\n[{}]",
            //         resource_context
            //             .data_routes
            //             .routers
            //             .iter()
            //             .map(|router| format!("{:?}", router))
            //             .collect::<Vec<_>>()
            //             .join(",\n")
            //     ),
            // );
            // resource.field(
            //     "data_routes.peers",
            //     &format_args!(
            //         "\n[{}]",
            //         resource_context
            //             .data_routes
            //             .peers
            //             .iter()
            //             .map(|peer| format!("{:?}", peer))
            //             .collect::<Vec<_>>()
            //             .join(",\n")
            //     ),
            // );
            // resource.field(
            //     "data_routes.clients",
            //     &format_args!(
            //         "\n[{}]",
            //         resource_context
            //             .data_routes
            //             .clients
            //             .iter()
            //             .map(|client| format!("{:?}", client))
            //             .collect::<Vec<_>>()
            //             .join(",\n")
            //     ),
            // );
            
            // resource
            //     .field("data_routes.peers", &resource_context.data_routes.peers)
            //     .field("data_routes.clients", &resource_context.data_routes.clients);
        }
        
        resource.field("children", &self.children);
        
        resource.finish()
    }
}

impl Resource{

    pub fn format_for_no_recursive(&self) -> String {
        format!("Resource {{ suffix: {}, full_expr: {}}}", self.suffix, self.expr())
    }

    pub fn format_excluding_matches(&self) -> String {
        let data_routes_str = match &self.context {
            Some(ctx) => format!(
                "data_routes: {{
                routers: [{:#?}],
                peers: [{:#?}],
                clients: [{:#?}]}}",
                ctx.data_routes.routers.iter()
                    .map(|router| format!("{:?}", router))
                    .collect::<Vec<_>>()
                    .join(",\n"),
                ctx.data_routes.peers.iter()
                    .map(|peer| format!("{:?}", peer))
                    .collect::<Vec<_>>()
                    .join(",\n"),
                ctx.data_routes.clients.iter()
                    .map(|client| format!("{:?}", client))
                    .collect::<Vec<_>>()
                    .join(",\n"),
            ),
            None => "data_routes: None".to_string(),
        };

        format!(
            "Resource {{ suffix: {}, children: {:?}, {}}}",
            self.suffix,
            self.children.keys().collect::<Vec<_>>(),
            data_routes_str
        )
    }
    
}

// impl Resource {
//     fn fmt_with_visited(&self, f: &mut fmt::Formatter<'_>, visited: String) -> fmt::Result {
//         if visited == self.suffix {
//             return write!(f, "Resource with suffix {} point to itself", self.suffix);
//         }
//         let visited = self.suffix.clone();
//         let mut resource = f.debug_struct("Resource");
        
//         resource.field("suffix", &self.suffix);
        
//         if let Some(resource_context) = &self.context {
//             if resource_context
//                         .data_routes
//                         .routers
//                         .iter()
//                         .flat_map(|router|router.iter())
//                         .any(|(_,(face_state, _,_))|face_state.contains_visited_suffix(&visited)){
//                             return write!(f, "Face_state's Resource contains cyclic suffix references");
//                         }




//             resource.field("matches", &resource_context.matches);
//             resource.field(
//                 "data_routes.routers",
//                 &format_args!(
//                     "\n[{}]",
//                     resource_context
//                         .data_routes
//                         .routers
//                         .iter()
//                         .map(|router| format!("{:?}", router))
//                         .collect::<Vec<_>>()
//                         .join(",\n")
//                 ),
//             );
//             resource.field(
//                 "data_routes.peers",
//                 &format_args!(
//                     "\n[{}]",
//                     resource_context
//                         .data_routes
//                         .peers
//                         .iter()
//                         .map(|peer| format!("{:?}", peer))
//                         .collect::<Vec<_>>()
//                         .join(",\n")
//                 ),
//             );
//             resource.field(
//                 "data_routes.clients",
//                 &format_args!(
//                     "\n[{}]",
//                     resource_context
//                         .data_routes
//                         .clients
//                         .iter()
//                         .map(|client| format!("{:?}", client))
//                         .collect::<Vec<_>>()
//                         .join(",\n")
//                 ),
//             );
            
//         }
        
//         resource.field("children", &self.children);
        
//         resource.finish()
//     }

//     pub fn has_visited_suffix(&self, visited: &str) -> bool {
//         // 如果有 context，递归检查
//         if let Some(context) = &self.context {
//             if context
//                 .matches
//                 .iter()
//                 .filter_map(|weak_resource| weak_resource.upgrade()) // 尝试升级 Weak<Resource>
//                 .any(|resource| resource.suffix == visited) // 检查 suffix 是否匹配
//                 // || context
//                 //     .data_routes
//                 //     .routers
//                 //     .iter()
//                 //     .flat_map(|router| router.iter())
//                 //     .any(|(_, direction)| {
//                 //         let (face_state, _, _) = direction;
//                 //         face_state.contains_visited_suffix(visited)
//                 //     })
//             {
//                 return true;
//             }
//             if context
//                 .matches
//                 .iter()
//                 .filter_map(|weak_resource| weak_resource.upgrade()) // 尝试升级 Weak<Resource>
//                 .any(|resource| resource.suffix == visited) // 检查 suffix 是否匹配
//                 // || context
//                 //     .data_routes
//                 //     .peers
//                 //     .iter()
//                 //     .flat_map(|router| router.iter())
//                 //     .any(|(_, direction)| {
//                 //         let (face_state, _, _) = direction;
//                 //         face_state.contains_visited_suffix(visited)
//                 //     })
//             {
//                 return true;
//             }
//             if context
//                 .matches
//                 .iter()
//                 .filter_map(|weak_resource| weak_resource.upgrade()) // 尝试升级 Weak<Resource>
//                 .any(|resource| resource.suffix == visited) // 检查 suffix 是否匹配
//                 // || context
//                 //     .data_routes
//                 //     .clients
//                 //     .iter()
//                 //     .flat_map(|router| router.iter())
//                 //     .any(|(_, direction)| {
//                 //         let (face_state, _, _) = direction;
//                 //         face_state.contains_visited_suffix(visited)
//                 //     })
//             {
//                 return true;
//             }
//         }
    
//         // 检查子节点
//         self.children.iter().any(|(child_suffix, child_resource)| {
//             child_suffix == visited || child_resource.has_visited_suffix(visited)
//         })
//     }
// }

// impl fmt::Debug for Resource {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let visited = String::new();
//         self.fmt_with_visited(f, visited)
//     }
    
// }

impl PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        self.expr() == other.expr()
    }
}
impl Eq for Resource {}

// NOTE: The `clippy::mutable_key_type` lint takes issue with the fact that `Resource` contains
// interior mutable data. A configuration option is used to assert that the accessed fields are
// not interior mutable in clippy.toml. Thus care should be taken to ensure soundness of this impl
// as Clippy will not warn about its usage in sets/maps.
impl Hash for Resource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expr().hash(state);
    }
}

impl Resource {
    fn new(parent: &Arc<Resource>, suffix: &str, context: Option<ResourceContext>) -> Resource {
        let nonwild_prefix = match &parent.nonwild_prefix {
            None => {
                if suffix.contains('*') {
                    Some((parent.clone(), String::from(suffix)))
                } else {
                    None
                }
            }
            Some((prefix, wildsuffix)) => Some((prefix.clone(), [wildsuffix, suffix].concat())),
        };

        Resource {
            parent: Some(parent.clone()),
            suffix: String::from(suffix),
            nonwild_prefix,
            children: HashMap::new(),
            context,
            session_ctxs: HashMap::new(),
        }
    }

    pub fn expr(&self) -> String {
        match &self.parent {
            Some(parent) => parent.expr() + &self.suffix,
            None => String::from(""),
        }
    }

    #[inline(always)]
    pub(crate) fn context(&self) -> &ResourceContext {
        self.context.as_ref().unwrap()
    }

    #[inline(always)]
    pub(crate) fn context_mut(&mut self) -> &mut ResourceContext {
        self.context.as_mut().unwrap()
    }

    #[inline(always)]
    pub(crate) fn matches(&self, other: &Arc<Resource>) -> bool {
        self.context
            .as_ref()
            .unwrap()
            .matches
            .iter()
            .any(|m| m.upgrade().is_some_and(|m| &m == other))
    }

    pub fn nonwild_prefix(res: &Arc<Resource>) -> (Option<Arc<Resource>>, String) {
        match &res.nonwild_prefix {
            None => (Some(res.clone()), "".to_string()),
            Some((nonwild_prefix, wildsuffix)) => {
                if !nonwild_prefix.expr().is_empty() {
                    (Some(nonwild_prefix.clone()), wildsuffix.clone())
                } else {
                    (None, res.expr())
                }
            }
        }
    }

    #[inline]
    pub(crate) fn data_route(&self, whatami: WhatAmI, context: NodeId) -> Option<Arc<Route>> {
        match &self.context {
            Some(ctx) => {
                if ctx.valid_data_routes {
                    ctx.data_routes.get_route(whatami, context)
                } else {
                    None
                }
            }

            None => None,
        }
    }

    #[inline(always)]
    pub(crate) fn query_route(
        &self,
        whatami: WhatAmI,
        context: NodeId,
    ) -> Option<Arc<QueryTargetQablSet>> {
        match &self.context {
            Some(ctx) => {
                if ctx.valid_query_routes {
                    ctx.query_routes.get_route(whatami, context)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    pub fn root() -> Arc<Resource> {
        Arc::new(Resource {
            parent: None,
            suffix: String::from(""),
            nonwild_prefix: None,
            children: HashMap::new(),
            context: None,
            session_ctxs: HashMap::new(),
        })
    }

    pub fn clean(res: &mut Arc<Resource>) {
        let mut resclone = res.clone();
        let mutres = get_mut_unchecked(&mut resclone);
        if let Some(ref mut parent) = mutres.parent {
            if Arc::strong_count(res) <= 3 && res.children.is_empty() {
                // consider only childless resource held by only one external object (+ 1 strong count for resclone, + 1 strong count for res.parent to a total of 3 )
                tracing::debug!("Unregister resource {}", res.expr());
                if let Some(context) = mutres.context.as_mut() {
                    for match_ in &mut context.matches {
                        let mut match_ = match_.upgrade().unwrap();
                        if !Arc::ptr_eq(&match_, res) {
                            let mutmatch = get_mut_unchecked(&mut match_);
                            if let Some(ctx) = mutmatch.context.as_mut() {
                                ctx.matches
                                    .retain(|x| !Arc::ptr_eq(&x.upgrade().unwrap(), res));
                            }
                        }
                    }
                }
                mutres.nonwild_prefix.take();
                {
                    get_mut_unchecked(parent).children.remove(&res.suffix);
                }
                Resource::clean(parent);
            }
        }
    }

    pub fn close(self: &mut Arc<Resource>) {
        let r = get_mut_unchecked(self);
        for c in r.children.values_mut() {
            Self::close(c);
        }
        r.parent.take();
        r.children.clear();
        r.nonwild_prefix.take();
        r.context.take();
        r.session_ctxs.clear();
    }

    #[cfg(test)]
    pub fn print_tree(from: &Arc<Resource>) -> String {
        let mut result = from.expr();
        println!("init_result:  {}",result);
        match &from.context{
            Some(resource_context)
                => {
                    println!("data_routes.routers: {:#?}",resource_context.data_routes.routers);
                    println!("data_routes.peers: {:#?}",resource_context.data_routes.peers);
                    println!("data_routes.clients: {:#?}",resource_context.data_routes.clients);
                    },
            _ => (),
        }
        result.push('\n');
        for child in from.children.values() {
            result.push_str(&Resource::print_tree(child));
        }
        result
    }

    pub fn format_one_layer(&self){
        
        
    }
    // pub fn print_resource_tree(from: &Arc<Resource>) {
    //     let result = from.expr();
    //     println!("full_string:  {}",result);
    //     println!("suffix:    {}", from.suffix);
    //     match &from.context{
    //         Some(resource_context)
    //             => {
    //                 println!("data_routes.routers: {:?}",resource_context.data_routes.routers);
    //                 println!("data_routes.peers: {:?}",resource_context.data_routes.peers);
    //                 println!("data_routes.clients: {:?}",resource_context.data_routes.clients);
    //                 },
    //         _ => (),
    //     }
    //     for child in from.children.values() {
    //         Resource::print_resource_tree(child);
    //     }
    // }


    pub fn make_resource(
        tables: &mut Tables,
        from: &mut Arc<Resource>,
        suffix: &str,
    ) -> Arc<Resource> {
        if suffix.is_empty() {
            Resource::upgrade_resource(from, tables.hat_code.new_resource());
            from.clone()
        } else if let Some(stripped_suffix) = suffix.strip_prefix('/') {
            let (chunk, rest) = match stripped_suffix.find('/') {
                Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                None => (suffix, ""),
            };

            match get_mut_unchecked(from).children.get_mut(chunk) {
                Some(res) => Resource::make_resource(tables, res, rest),
                None => {
                    let mut new = Arc::new(Resource::new(from, chunk, None));
                    if tracing::enabled!(tracing::Level::DEBUG) && rest.is_empty() {
                        tracing::debug!("Register resource {}", new.expr());
                    }
                    let res = Resource::make_resource(tables, &mut new, rest);
                    get_mut_unchecked(from)
                        .children
                        .insert(String::from(chunk), new);
                    res
                }
            }
        } else {
            match from.parent.clone() {
                Some(mut parent) => {
                    Resource::make_resource(tables, &mut parent, &[&from.suffix, suffix].concat())
                }
                None => {
                    let (chunk, rest) = match suffix[1..].find('/') {
                        Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                        None => (suffix, ""),
                    };

                    match get_mut_unchecked(from).children.get_mut(chunk) {
                        Some(res) => Resource::make_resource(tables, res, rest),
                        None => {
                            let mut new = Arc::new(Resource::new(from, chunk, None));
                            if tracing::enabled!(tracing::Level::DEBUG) && rest.is_empty() {
                                tracing::debug!("Register resource {}", new.expr());
                            }
                            let res = Resource::make_resource(tables, &mut new, rest);
                            get_mut_unchecked(from)
                                .children
                                .insert(String::from(chunk), new);
                            res
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub fn get_resource(from: &Arc<Resource>, suffix: &str) -> Option<Arc<Resource>> {
        if suffix.is_empty() {
            Some(from.clone())
        //If there is a '/'in the first
        } else if let Some(stripped_suffix) = suffix.strip_prefix('/') {
            //get the '/' in the first off
            let (chunk, rest) = match stripped_suffix.find('/') {
                Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                None => (suffix, ""),
            };
            //from the hashmap in the children to get the child resource (its hash key must be the chunk)
            match from.children.get(chunk) {
                // If there is, recursively get the rest until the last resource, return back
                Some(res) => Resource::get_resource(res, rest),
                None => None,
            }
        //If there is no '/' in the first
        } else {
            // Get the parent resource,
            match &from.parent {
                // If there is a parent node, then get the resource from parent'children (in your same layer) and find concat your suffix and the suffix to find
                Some(parent) => Resource::get_resource(parent, &[&from.suffix, suffix].concat()),
                None => {
                    let (chunk, rest) = match suffix[1..].find('/') {
                        Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                        None => (suffix, ""),
                    };
                    // find the chunk from your children, and keep going
                    match from.children.get(chunk) {
                        Some(res) => Resource::get_resource(res, rest),
                        None => None,
                    }
                }
            }
        }
    }

    // To Be Removed
    #[inline]
    pub fn check_resource(from: &Arc<Resource>, suffix: &str) -> Arc<Resource> {
        if suffix.is_empty() {
            from.clone()
        } else if let Some(stripped_suffix) = suffix.strip_prefix('/') {
            let (chunk, rest) = match stripped_suffix.find('/') {
                Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                None => (suffix, ""),
            };
            match from.children.get(chunk) {
                Some(res) => Resource::check_resource(res, rest),
                None => panic!("Resource node not found for chunk: '{}'", chunk),
            }
        } else {
            match &from.parent {
                Some(parent) => Resource::check_resource(parent, &[&from.suffix, suffix].concat()),
                None => {
                    let (chunk, rest) = match suffix[1..].find('/') {
                        Some(idx) => (&suffix[0..(idx + 1)], &suffix[(idx + 1)..]),
                        None => (suffix, ""),
                    };
                    match from.children.get(chunk) {
                        Some(res) => Resource::check_resource(res, rest),
                        None => panic!("Resource node not found for chunk: '{}'", chunk),
                    }
                }
            }
        }
    }

    fn fst_chunk(key_expr: &keyexpr) -> (&keyexpr, Option<&keyexpr>) {
        match key_expr.as_bytes().iter().position(|c| *c == b'/') {
            Some(pos) => {
                let left = &key_expr.as_bytes()[..pos];
                let right = &key_expr.as_bytes()[pos + 1..];
                unsafe {
                    (
                        keyexpr::from_slice_unchecked(left),
                        Some(keyexpr::from_slice_unchecked(right)),
                    )
                }
            }
            None => (key_expr, None),
        }
    }

    #[inline]
    pub fn decl_key(
        res: &Arc<Resource>,
        face: &mut Arc<FaceState>,
        push: bool,
    ) -> WireExpr<'static> {
        let (nonwild_prefix, wildsuffix) = Resource::nonwild_prefix(res);
        match nonwild_prefix {
            Some(mut nonwild_prefix) => {
                if let Some(ctx) = get_mut_unchecked(&mut nonwild_prefix)
                    .session_ctxs
                    .get(&face.id)
                {
                    if let Some(expr_id) = ctx.remote_expr_id {
                        return WireExpr {
                            scope: expr_id,
                            suffix: wildsuffix.into(),
                            mapping: Mapping::Receiver,
                        };
                    }
                    if let Some(expr_id) = ctx.local_expr_id {
                        return WireExpr {
                            scope: expr_id,
                            suffix: wildsuffix.into(),
                            mapping: Mapping::Sender,
                        };
                    }
                }
                if push
                    || face.remote_key_interests.values().any(|res| {
                        res.as_ref()
                            .map(|res| res.matches(&nonwild_prefix))
                            .unwrap_or(true)
                    })
                {
                    let ctx = get_mut_unchecked(&mut nonwild_prefix)
                        .session_ctxs
                        .entry(face.id)
                        .or_insert_with(|| Arc::new(SessionContext::new(face.clone())));
                    let expr_id = face.get_next_local_id();
                    get_mut_unchecked(ctx).local_expr_id = Some(expr_id);
                    get_mut_unchecked(face)
                        .local_mappings
                        .insert(expr_id, nonwild_prefix.clone());
                    // println!("'face.local_mappings' is about to be printed now.");
                    // println!("{:?}",&face.local_mappings);
                    // println!();
                    face.primitives.send_declare(RoutingContext::with_expr(
                        Declare {
                            interest_id: None,
                            ext_qos: ext::QoSType::DECLARE,
                            ext_tstamp: None,
                            ext_nodeid: ext::NodeIdType::DEFAULT,
                            body: DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                                id: expr_id,
                                wire_expr: nonwild_prefix.expr().into(),
                            }),
                        },
                        nonwild_prefix.expr(),
                    ));
                    face.update_interceptors_caches(&mut nonwild_prefix);
                    WireExpr {
                        scope: expr_id,
                        suffix: wildsuffix.into(),
                        mapping: Mapping::Sender,
                    }
                } else {
                    res.expr().into()
                }
            }
            None => wildsuffix.into(),
        }
    }

    #[inline]
    pub fn get_best_key<'a>(prefix: &Arc<Resource>, suffix: &'a str, sid: usize) -> WireExpr<'a> {
        fn get_best_key_<'a>(
            prefix: &Arc<Resource>,
            suffix: &'a str,
            sid: usize,
            checkclildren: bool,
        ) -> WireExpr<'a> {
            if checkclildren && !suffix.is_empty() {
                let (chunk, rest) = suffix.split_at(suffix.find('/').unwrap_or(suffix.len()));
                if let Some(child) = prefix.children.get(chunk) {
                    return get_best_key_(child, rest, sid, true);
                }
            }
            if let Some(ctx) = prefix.session_ctxs.get(&sid) {
                if let Some(expr_id) = ctx.remote_expr_id {
                    return WireExpr {
                        scope: expr_id,
                        suffix: suffix.into(),
                        mapping: Mapping::Receiver,
                    };
                } else if let Some(expr_id) = ctx.local_expr_id {
                    return WireExpr {
                        scope: expr_id,
                        suffix: suffix.into(),
                        mapping: Mapping::Sender,
                    };
                }
            }
            match &prefix.parent {
                Some(parent) => {
                    get_best_key_(parent, &[&prefix.suffix, suffix].concat(), sid, false).to_owned()
                }
                None => suffix.into(),
            }
        }
        get_best_key_(prefix, suffix, sid, true)
    }

    pub fn get_matches(tables: &Tables, key_expr: &keyexpr) -> Vec<Weak<Resource>> {
        fn recursive_push(from: &Arc<Resource>, matches: &mut Vec<Weak<Resource>>) {
            if from.context.is_some() {
                matches.push(Arc::downgrade(from));
            }
            for child in from.children.values() {
                recursive_push(child, matches)
            }
        }
        fn get_matches_from(
            key_expr: &keyexpr,
            from: &Arc<Resource>,
            matches: &mut Vec<Weak<Resource>>,
        ) {
            if from.parent.is_none() || from.suffix == "/" {
                for child in from.children.values() {
                    get_matches_from(key_expr, child, matches);
                }
                return;
            }
            let suffix: &keyexpr = from
                .suffix
                .strip_prefix('/')
                .unwrap_or(&from.suffix)
                .try_into()
                .unwrap();
            let (chunk, rest) = Resource::fst_chunk(key_expr);
            if chunk.intersects(suffix) {
                match rest {
                    None => {
                        if chunk.as_bytes() == b"**" {
                            recursive_push(from, matches)
                        } else {
                            if from.context.is_some() {
                                matches.push(Arc::downgrade(from));
                            }
                            if suffix.as_bytes() == b"**" {
                                for child in from.children.values() {
                                    get_matches_from(key_expr, child, matches)
                                }
                            }
                            if let Some(child) =
                                from.children.get("/**").or_else(|| from.children.get("**"))
                            {
                                if child.context.is_some() {
                                    matches.push(Arc::downgrade(child))
                                }
                            }
                        }
                    }
                    Some(rest) if rest.as_bytes() == b"**" => recursive_push(from, matches),
                    Some(rest) => {
                        let recheck_keyexpr_one_level_lower =
                            chunk.as_bytes() == b"**" || suffix.as_bytes() == b"**";
                        for child in from.children.values() {
                            get_matches_from(rest, child, matches);
                            if recheck_keyexpr_one_level_lower {
                                get_matches_from(key_expr, child, matches)
                            }
                        }
                        if recheck_keyexpr_one_level_lower {
                            get_matches_from(rest, from, matches)
                        }
                    }
                };
            }
        }
        let mut matches = Vec::new();
        get_matches_from(key_expr, &tables.root_res, &mut matches);
        let mut i = 0;
        while i < matches.len() {
            let current = matches[i].as_ptr();
            let mut j = i + 1;
            while j < matches.len() {
                if std::ptr::eq(current, matches[j].as_ptr()) {
                    matches.swap_remove(j);
                } else {
                    j += 1
                }
            }
            i += 1
        }
        matches
    }

    pub fn match_resource(_tables: &Tables, res: &mut Arc<Resource>, matches: Vec<Weak<Resource>>) {
        if res.context.is_some() {
            for match_ in &matches {
                let mut match_ = match_.upgrade().unwrap();
                get_mut_unchecked(&mut match_)
                    .context_mut()
                    .matches
                    .push(Arc::downgrade(res));
            }
            get_mut_unchecked(res).context_mut().matches = matches;
        } else {
            tracing::error!("Call match_resource() on context less res {}", res.expr());
        }
    }

    pub fn upgrade_resource(res: &mut Arc<Resource>, hat: Box<dyn Any + Send + Sync>) {
        if res.context.is_none() {
            get_mut_unchecked(res).context = Some(ResourceContext::new(hat));
        }
    }

    pub(crate) fn get_ingress_cache(&self, face: &Face) -> Option<&Box<dyn Any + Send + Sync>> {
        self.session_ctxs
            .get(&face.state.id)
            .and_then(|ctx| ctx.in_interceptor_cache.as_ref())
    }

    pub(crate) fn get_egress_cache(&self, face: &Face) -> Option<&Box<dyn Any + Send + Sync>> {
        self.session_ctxs
            .get(&face.state.id)
            .and_then(|ctx| ctx.e_interceptor_cache.as_ref())
    }
}
//TODO see what done first before register_expr
pub(crate) fn register_expr(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    expr_id: ExprId,
    expr: &WireExpr,
) {
    // get the Reource from 3 different sources, if the expr.scope == 0, it will return the root_resource
    // but if the expr_scope is not 0, it will depend on its expr.Mapping, if it's sender, get it from remote_mapping(key: expr_id)
    // if it's receiver, get it from local_mapping's hashmap(key: expr_id)
    let rtables = zread!(tables.tables);
    match rtables
        .get_mapping(face, &expr.scope, expr.mapping)
        .cloned()
    {
        // If get it(the scope is founded(?)), get the resource from remote_mapping with it's expr_id
        // Since only one router will receive the DeclareKeyExpr
        Some(mut prefix) => match face.remote_mappings.get(&expr_id) {
            // get the resource from remote_mapping hashmap, if it's there,
            Some(res) => {
                // then get the scope's full expression(fullexpr)
                let mut fullexpr = prefix.expr();
                // concat the fullexpr and the WireExpr's suffix (info fullexpr)
                fullexpr.push_str(expr.suffix.as_ref());
                // if the remote_mapping fullexpr isn't same as the fullexpr(the scope's fullexpr + WireExpr's suffix), it's error
                if res.expr() != fullexpr {
                    tracing::error!(
                        "{} Resource {} remapped. Remapping unsupported!",
                        face,
                        expr_id
                    );
                }
            }
            // If the expr_id is not in the remote_mapping row, 
            None => {
                // Get the resource from the scope resource tree, find the Wire_expr's suffix resource
                let res = Resource::get_resource(&prefix, &expr.suffix);
                let (mut res, mut wtables) = if res
                    .as_ref()
                    .map(|r| r.context.is_some())
                    .unwrap_or(false)
                //if the scope prefix + suffix's res.context is there
                {
                    // drop the read table here, we don't need it anymore cause we don't need to make resource()
                    drop(rtables);
                    let wtables = zwrite!(tables.tables);
                    (res.unwrap(), wtables)
                //if the res.context is not there (no data route)
                } else {
                    let mut fullexpr = prefix.expr();
                    fullexpr.push_str(expr.suffix.as_ref());
                    // new the full_keyexpression 
                    let mut matches = keyexpr::new(fullexpr.as_str())
                        .map(|ke| Resource::get_matches(&rtables, ke))
                        .unwrap_or_default();
                    drop(rtables);
                    let mut wtables = zwrite!(tables.tables);
                    //make the resource from the scope resource, return the leaf resource (res)
                    let mut res =
                        Resource::make_resource(&mut wtables, &mut prefix, expr.suffix.as_ref());
                    matches.push(Arc::downgrade(&res));
                    Resource::match_resource(&wtables, &mut res, matches);
                    (res, wtables)
                };
                let ctx = get_mut_unchecked(&mut res)
                    .session_ctxs
                    .entry(face.id)
                    .or_insert_with(|| Arc::new(SessionContext::new(face.clone())));

                get_mut_unchecked(ctx).remote_expr_id = Some(expr_id);

                get_mut_unchecked(face)
                    .remote_mappings
                    .insert(expr_id, res.clone());
                // println!("'face.remote_mappings' is about to be printed now.");
                // println!("{:?}",&face.remote_mappings);
                // println!();
                wtables.update_matches_routes(&mut res);
                face.update_interceptors_caches(&mut res);
                drop(wtables);
            }
        },
        None => tracing::error!(
            "{} Declare resource with unknown scope {}!",
            face,
            expr.scope
        ),
    }
}

pub(crate) fn unregister_expr(tables: &TablesLock, face: &mut Arc<FaceState>, expr_id: ExprId) {
    let wtables = zwrite!(tables.tables);
    match get_mut_unchecked(face).remote_mappings.remove(&expr_id) {
        Some(mut res) => Resource::clean(&mut res),
        None => tracing::error!("{} Undeclare unknown resource!", face),
    }
    drop(wtables);
}

pub(crate) fn register_expr_interest(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    id: InterestId,
    expr: Option<&WireExpr>,
) {
    if let Some(expr) = expr {
        let rtables = zread!(tables.tables);
        match rtables
            .get_mapping(face, &expr.scope, expr.mapping)
            .cloned()
        {
            Some(mut prefix) => {
                let res = Resource::get_resource(&prefix, &expr.suffix);
                let (res, wtables) = if res.as_ref().map(|r| r.context.is_some()).unwrap_or(false) {
                    drop(rtables);
                    let wtables = zwrite!(tables.tables);
                    (res.unwrap(), wtables)
                } else {
                    let mut fullexpr = prefix.expr();
                    fullexpr.push_str(expr.suffix.as_ref());
                    let mut matches = keyexpr::new(fullexpr.as_str())
                        .map(|ke| Resource::get_matches(&rtables, ke))
                        .unwrap_or_default();
                    drop(rtables);
                    let mut wtables = zwrite!(tables.tables);
                    let mut res =
                        Resource::make_resource(&mut wtables, &mut prefix, expr.suffix.as_ref());
                    matches.push(Arc::downgrade(&res));
                    Resource::match_resource(&wtables, &mut res, matches);
                    (res, wtables)
                };
                get_mut_unchecked(face)
                    .remote_key_interests
                    .insert(id, Some(res));
                drop(wtables);
            }
            None => tracing::error!(
                "Declare keyexpr interest with unknown scope {}!",
                expr.scope
            ),
        }
    } else {
        let wtables = zwrite!(tables.tables);
        get_mut_unchecked(face)
            .remote_key_interests
            .insert(id, None);
        drop(wtables);
    }
}

pub(crate) fn unregister_expr_interest(
    tables: &TablesLock,
    face: &mut Arc<FaceState>,
    id: InterestId,
) {
    let wtables = zwrite!(tables.tables);
    get_mut_unchecked(face).remote_key_interests.remove(&id);
    drop(wtables);
}
