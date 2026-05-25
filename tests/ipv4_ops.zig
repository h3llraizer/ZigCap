const std = @import("std");
const zigcap = @import("zigcap");

const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Layer.LayerOwner;
const TLVOwner = zigcap.Layer.TLVOwner;
const LayerIface = zigcap.LayerIface;
const ARP = zigcap.ARP;
const IPv4 = zigcap.IPv4;

const Eth = zigcap.Eth;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

//   test "build rr opt" {
//       print("\nTESTING RR OPTION.\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var rr = try IPv4.IPv4_Options.RecordRoute.init(tlv_owner);
//       defer rr.deinit();
//
//       try rr.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//       try rr.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
//       try rr.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));
//
//       const ips = try rr.get_ip_list(allocator) orelse {
//           try expect(false); // no ips found
//           return;
//       };
//
//       try expect(rr.get_length() == ((@sizeOf(IPv4.IPv4Address) * 3) +
//           IPv4.IPv4_Options.RecordRoute.TLVHeaderLength));
//
//       for (ips) |ip| {
//           const ip_str = try ip.to_string(allocator);
//           print("{s}\n", .{ip_str});
//           allocator.free(ip_str);
//       }
//
//       defer allocator.free(ips);
//
//       try expect(rr.get_ip_count() == 3);
//
//       try expect(rr.get_ip_count() == ips.len);
//
//       try rr.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//
//       const ip_list = try rr.get_ip_list(allocator) orelse {
//           try expect(false); // ip list not found in RR option
//           return;
//       };
//
//       defer allocator.free(ip_list);
//
//       try expect(ip_list.len == 2);
//
//       try expect(rr.get_length() == 11);
//
//       for (ip_list) |ip| {
//           const str = try ip.to_string(allocator);
//           print("{s}\n", .{str});
//           allocator.free(str);
//       }
//
//       var opt = IPv4.IPv4Option{ .record_route = rr };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       try ipv4_layer.add_option(&opt);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var cur = options.first;
//       var count: usize = 0;
//       while (cur) |option| {
//           count += 1;
//           const next = option.get_next();
//           try expect(option.get_opt_type() == IPv4.IPOptionType.RecordRoute);
//           cur = next;
//       }
//
//       try expect(count == 1);
//
//       try expect(ipv4_layer.get_data().len == 32);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       var rr_opt = ipv4_layer.get_first_op() orelse {
//           try expect(false); // failed to get first opt
//           return;
//       };
//
//       try expect(rr_opt.get_opt_type() == .RecordRoute);
//
//       print("rr opt data: ({}) {x}\n", .{ rr_opt.get_data().len, rr_opt.get_data() });
//
//       try expect(rr_opt.get_length() == 11);
//
//       try expect(rr_opt.get_data().len == 11);
//
//       try rr_opt.record_route.remove_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
//
//       try expect(rr_opt.get_length() == 7);
//
//       try expect(rr_opt.get_data().len == 7);
//
//       var iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
//       print("{s}\n", .{iphdr_str});
//       allocator.free(iphdr_str);
//
//       try expect(ipv4_layer.get_data().len == 28);
//
//       try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//
//       try expect(rr_opt.get_length() == 11);
//
//       try expect(rr_opt.get_data().len == 11);
//
//       try expect(ipv4_layer.get_data().len == 32);
//
//       try expect(ipv4_layer.get_immutable_header().get_length() == 32);
//
//       try expect(ipv4_layer.get_immutable_header().get_ihl() == 8);
//
//       try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("0.0.0.0"));
//
//       try expect(rr_opt.record_route.get_length() == 15);
//
//       try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("0.0.0.0"));
//
//       try expect(rr_opt.record_route.get_length() == 19);
//
//       print("ipv4 data: {x}\n", .{ipv4_layer.get_data()});
//
//       iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
//       print("{s}\n", .{iphdr_str});
//       allocator.free(iphdr_str);
//
//       if (ipv4_layer.check_pad()) |pad_len| {
//           print("pad bytes: {}\n", .{pad_len});
//       }
//   }
//
//   test "build lsr opt" {
//       print("\nTESTING LSR OPTION.\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var lsr = try IPv4.IPv4_Options.LooseSourceRoute.init(tlv_owner);
//       defer lsr.deinit();
//
//       try lsr.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//       try lsr.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
//       try lsr.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));
//
//       const ips = try lsr.get_ip_list(allocator) orelse {
//           try expect(false); // no ips found
//           return;
//       };
//
//       defer allocator.free(ips);
//
//       try expect(lsr.get_ip_count() == 3);
//
//       try expect(lsr.get_ip_count() == ips.len);
//
//       try lsr.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//
//       const ip_list = try lsr.get_ip_list(allocator) orelse {
//           try expect(false); // ip list not found
//           return;
//       };
//
//       defer allocator.free(ip_list);
//
//       for (ip_list) |ip| {
//           const str = try ip.to_string(allocator);
//           allocator.free(str);
//       }
//
//       var opt = IPv4.IPv4Option{ .loose_route = lsr };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       try ipv4_layer.add_option(&opt);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var cur = options.first;
//       var count: usize = 0;
//       while (cur) |option| {
//           count += 1;
//           const next = option.get_next();
//           try expect(option.get_opt_type() == IPv4.IPOptionType.LooseSourceRoute);
//           cur = next;
//       }
//
//       try expect(count == 1);
//
//       try expect(ipv4_layer.get_data().len == 32);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       const iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
//       print("{s}\n", .{iphdr_str});
//       allocator.free(iphdr_str);
//   }
//
//   test "build ssr opt" {
//       print("\nTESTING SSR OPTION.\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ssr = try IPv4.IPv4_Options.StrictSourceRoute.init(tlv_owner);
//       defer ssr.deinit();
//
//       try ssr.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//       try ssr.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
//       try ssr.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));
//
//       const ips = try ssr.get_ip_list(allocator) orelse {
//           try expect(false); // no ips found
//           return;
//       };
//
//       defer allocator.free(ips);
//
//       try expect(ssr.get_ip_count() == 3);
//
//       try expect(ssr.get_ip_count() == ips.len);
//
//       try ssr.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
//
//       const ip_list = try ssr.get_ip_list(allocator) orelse {
//           try expect(false); // ip list not found
//           return;
//       };
//
//       defer allocator.free(ip_list);
//
//       for (ip_list) |ip| {
//           const str = try ip.to_string(allocator);
//           allocator.free(str);
//       }
//
//       var opt = IPv4.IPv4Option{ .strict_route = ssr };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       try ipv4_layer.add_option(&opt);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var cur = options.first;
//       var count: usize = 0;
//       while (cur) |option| {
//           count += 1;
//           const next = option.get_next();
//           try expect(option.get_opt_type() == IPv4.IPOptionType.StrictSourceRoute);
//           cur = next;
//       }
//
//       try expect(count == 1);
//
//       try expect(ipv4_layer.get_data().len == 32);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       const iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
//       print("{s}\n", .{iphdr_str});
//       allocator.free(iphdr_str);
//   }
//
//   test "build ra opt" {
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       var tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       defer tmp_owner.deinit();
//
//       var ra = try IPv4.IPv4_Options.RouterAlert.init(tlv_owner);
//       defer ra.deinit();
//
//       try ra.set_ra_val(0x0000);
//
//       var opt = IPv4.IPv4Option{ .router_alert = ra };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       try ipv4_layer.add_option(&opt);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var cur = options.first;
//
//       while (cur) |option| {
//           cur = option.get_next();
//       }
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//   }
//
//   test "build timestamp opt" {
//       print("\nTESTING TIMESTAMP OPTION.\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ts_opt = try IPv4.IPv4_Options.Timestamp.init(tlv_owner);
//       defer ts_opt.deinit();
//
//       try ts_opt.set_mode_flag(IPv4.IPv4_Options.Timestamp.Mode.APPEND_ADDRESSES);
//       try ts_opt.set_overflow(0);
//
//       print("ts_opt data: {x}\n", .{ts_opt.get_data()});
//
//       var rec = IPv4.IPv4_Options.TimestampRecord{
//           .timestamp = 999999,
//           .ip = try IPv4.IPv4Address.init_from_string("172.72.3.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       print("ts_opt data: {x}\n", .{ts_opt.get_data()});
//
//       rec = .{
//           .timestamp = 111111,
//           .ip = try IPv4.IPv4Address.init_from_string("10.1.1.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       print("ts_opt data: {x}\n", .{ts_opt.get_data()});
//
//       var records = try ts_opt.get_records(allocator) orelse {
//           try expect(false); // records not found
//           return;
//       };
//
//       var cur = records.first;
//       while (cur) |record| {
//           if (record.ip) |ipv4| {
//               const ipv4_str = try ipv4.to_string(allocator);
//               //    print("IP: {s} ", .{ipv4_str});
//               allocator.free(ipv4_str);
//           }
//           //  print("TS: {d}\n", .{record.timestamp});
//           cur = record.next_record;
//       }
//
//       records.deinit(allocator);
//
//       print("ts_data: ({}) {x}\n", .{ ts_opt.get_data().len, ts_opt.get_data() });
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       var opt = IPv4.IPv4Option{ .timestamp = ts_opt };
//
//       try ipv4_layer.add_option(&opt);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var cur_opt = options.first;
//
//       while (cur_opt) |option| {
//           cur_opt = option.get_next();
//       }
//
//       print("ipv4_layer data: ({}) {x}\n", .{ ipv4_layer.get_data().len, ipv4_layer.get_data() });
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       //   var option = try ipv4_layer.get_options(allocator);
//       //   while (option) |cur_opt| {
//       //       print("{any} {x} is layer owned: {any}\n", .{
//       //           cur_opt.get_opt_type(),
//       //           cur_opt.get_data(),
//       //           cur_opt.timestamp.owner.is_layer_owned(),
//       //       });
//       //       const next = cur_opt.get_next();
//       //       if (cur_opt.get_opt_type() == .Timestamp) {
//       //           var ts_records = try cur_opt.timestamp.get_records(allocator) orelse {
//       //               try expect(false);
//       //               return;
//       //           };
//       //           defer ts_records.deinit(allocator);
//       //           var ts_record = ts_records.first;
//       //           while (ts_record) |record| {
//       //               if (record.ip) |ip_addr| {
//       //                   const ip_str = try ip_addr.to_string(allocator);
//       //                   print("ip: {s}\n", .{ip_str});
//       //                   allocator.free(ip_str);
//       //               }
//       //               print("ts: {d}\n", .{record.timestamp});
//       //               ts_record = record.next_record;
//       //           }
//       //       }
//       //       allocator.destroy(cur_opt);
//       //       option = next;
//       //   }
//
//       var ipv4_opt = ipv4_layer.get_first_op() orelse {
//           try expect(false);
//           return;
//       };
//
//       try expect(ipv4_opt.get_opt_type() == IPv4.IPOptionType.Timestamp);
//
//       rec = .{ .ip = try IPv4.IPv4Address.init_from_string("192.168.1.254"), .timestamp = 333333 };
//
//       try ipv4_opt.timestamp.add_ts_record(rec);
//
//       try ipv4_opt.timestamp.remove_ts_record(rec);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       try expect(ipv4_layer.get_immutable_header().get_length() == 40);
//
//       try expect(ipv4_layer.get_immutable_header().get_ihl() == 10);
//   }
//
//   test "build timestamp opt in packet" {
//       print("\nTESTING TIMESTAMP OPTION IN PACKET.\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       var tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       defer tmp_owner.deinit();
//
//       var ts_opt = try IPv4.IPv4_Options.Timestamp.init(tlv_owner);
//       defer ts_opt.deinit();
//
//       try ts_opt.set_mode_flag(IPv4.IPv4_Options.Timestamp.Mode.APPEND_ADDRESSES);
//       try ts_opt.set_overflow(0);
//
//       var rec = IPv4.IPv4_Options.TimestampRecord{
//           .timestamp = 999999,
//           .ip = try IPv4.IPv4Address.init_from_string("172.72.3.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       rec = .{
//           .timestamp = 111111,
//           .ip = try IPv4.IPv4Address.init_from_string("10.1.1.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       var records = try ts_opt.get_records(allocator) orelse {
//           try expect(false); // records not found
//           return;
//       };
//
//       var cur = records.first;
//       while (cur) |record| {
//           if (record.ip) |ipv4| {
//               const ipv4_str = try ipv4.to_string(allocator);
//               //         print("IP: {s} ", .{ipv4_str});
//               allocator.free(ipv4_str);
//           }
//           //      print("TS: {d}\n", .{record.timestamp});
//           cur = record.next_record;
//       }
//
//       records.deinit(allocator);
//
//       var opt = IPv4.IPv4Option{ .timestamp = ts_opt };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       try ipv4_layer.add_option(&opt);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false);
//           return;
//       };
//
//       defer options.deinit(allocator);
//       var cur_opt = options.first;
//       while (cur_opt) |option| {
//           //     print("{any} {x} is layer owned: {any}\n", .{
//           //         option.get_opt_type(),
//           //         option.get_data(),
//           //         option.timestamp.owner.is_layer_owned(),
//           //     });
//           const next = opt.get_next();
//           if (option.get_opt_type() == .Timestamp) {
//               var ts_records = try option.timestamp.get_records(allocator) orelse {
//                   try expect(false);
//                   return;
//               };
//               defer ts_records.deinit(allocator);
//               var ts_record = ts_records.first;
//               while (ts_record) |record| {
//                   if (record.ip) |ip_addr| {
//                       const ip_str = try ip_addr.to_string(allocator);
//                       //                 print("ip: {s}\n", .{ip_str});
//                       allocator.free(ip_str);
//                   }
//                   //            print("ts: {d}\n", .{record.timestamp});
//                   ts_record = record.next_record;
//               }
//           }
//           cur_opt = next;
//       }
//
//       var ipv4_opt = ipv4_layer.get_first_op() orelse {
//           try expect(false);
//           return;
//       };
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       try expect(ipv4_opt.get_opt_type() == IPv4.IPOptionType.Timestamp);
//
//       rec = .{ .ip = try IPv4.IPv4Address.init_from_string("192.168.1.254"), .timestamp = 333333 };
//
//       try ipv4_opt.timestamp.add_ts_record(rec);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       try ipv4_opt.timestamp.remove_ts_record(rec);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       var packet = try Packet.create(allocator, allocator);
//       defer packet.deinit();
//
//       var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, ipv4_layer.owner);
//
//       _ = try packet.add_layer(&ipv4_layer_iface);
//
//       if (packet.get_layer_of_type(IPv4.IPv4Layer)) |ip_layer| {
//           var first_opt = ip_layer.get_first_op() orelse {
//               try expect(false); // first op not found in packet ipv4 layer
//               return;
//           };
//           try first_opt.timestamp.add_ts_record(rec);
//
//           try expect(ip_layer.get_immutable_header().dscp_ecn == 0);
//           try expect(first_opt.timestamp.get_ptr() == 5);
//           //   print("data: {x}\n", .{first_opt.timestamp.get_data()});
//       } else {
//           try expect(false); // ip layer not found in packet
//           return;
//       }
//   }
//
//   test "build multiple options" {
//       print("\nTESTING BUILD MULTIPLE OPTIONS\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ts_opt = try IPv4.IPv4_Options.Timestamp.init(tlv_owner);
//       defer ts_opt.deinit();
//
//       try ts_opt.set_mode_flag(IPv4.IPv4_Options.Timestamp.Mode.APPEND_ADDRESSES);
//       try ts_opt.set_overflow(0);
//
//       var rec = IPv4.IPv4_Options.TimestampRecord{
//           .timestamp = 999999,
//           .ip = try IPv4.IPv4Address.init_from_string("172.72.3.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       rec = .{
//           .timestamp = 111111,
//           .ip = try IPv4.IPv4Address.init_from_string("10.1.1.1"),
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       print("timestamp ts_opt length: {}\n", .{ts_opt.get_data().len});
//
//       var records = try ts_opt.get_records(allocator) orelse {
//           try expect(false); // records not found
//           return;
//       };
//
//       var cur = records.first;
//       while (cur) |record| {
//           if (record.ip) |ipv4| {
//               const ipv4_str = try ipv4.to_string(allocator);
//               //print("IP: {s} ", .{ipv4_str});
//               allocator.free(ipv4_str);
//           }
//           //print("TS: {d}\n", .{record.timestamp});
//           cur = record.next_record;
//       }
//
//       records.deinit(allocator);
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       var opt = IPv4.IPv4Option{ .timestamp = ts_opt };
//
//       try ipv4_layer.add_option(&opt);
//
//       var ra = try IPv4.IPv4_Options.RouterAlert.init(tlv_owner);
//       defer ra.deinit();
//
//       try ra.set_ra_val(0x0000);
//
//       var opt1 = IPv4.IPv4Option{ .router_alert = ra };
//
//       try ipv4_layer.add_option(&opt1);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       var ipv4_opt = ipv4_layer.get_first_op() orelse {
//           try expect(false);
//           return;
//       };
//
//       try expect(ipv4_opt.get_opt_type() == IPv4.IPOptionType.Timestamp);
//
//       rec = .{ .ip = try IPv4.IPv4Address.init_from_string("192.168.1.254"), .timestamp = 333333 };
//
//       try ipv4_opt.timestamp.add_ts_record(rec);
//
//       try ipv4_opt.timestamp.remove_ts_record(rec);
//
//       try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);
//
//       var options = try ipv4_layer.get_options(allocator) orelse {
//           try expect(false); // failed to get options
//           return;
//       };
//
//       defer options.deinit(allocator);
//
//       var count: usize = 1;
//       var option = options.first;
//       while (option) |cur_opt| {
//           print("{}. type: {any}\ndata: ({}) {x}\ntlv_length:{}\nlength {}\n\n", .{
//               count,
//               cur_opt.get_opt_type(),
//               cur_opt.get_data().len,
//               cur_opt.get_data(),
//               cur_opt.get_tlv_length(),
//               cur_opt.get_data()[1],
//           });
//
//           const next = cur_opt.get_next();
//           count += 1;
//           option = next;
//       }
//   }
//
//   test "build timestamp option" {
//       print("\nTESTING BUILD MULTIPLE OPTIONS\n", .{});
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const buf = try allocator.alignedAlloc(u8, std.mem.Alignment.@"2", 4);
//       @memset(buf, 0);
//
//       buf[0] = @intFromEnum(IPv4.IPv4_Options.IPOptionType.Timestamp);
//       buf[1] = IPv4.IPv4_Options.Timestamp.TLVHeaderLength;
//       buf[2] = 5;
//       buf[3] = 0;
//
//       const tlv_owner = TLVOwner{ .owned_buffer = try .init(buf, allocator) };
//
//       var ts_opt = try IPv4.IPv4_Options.Timestamp.init(tlv_owner);
//
//       defer ts_opt.deinit();
//
//       try ts_opt.set_mode_flag(IPv4.IPv4_Options.Timestamp.Mode.APPEND_ADDRESSES);
//       try ts_opt.set_overflow(0);
//
//       try expect(ts_opt.get_mode_flag() == IPv4.IPv4_Options.Timestamp.Mode.APPEND_ADDRESSES);
//       try expect(ts_opt.get_overflow() == 0);
//
//       const ip0 = try IPv4.IPv4Address.init_from_string("172.72.3.1");
//
//       const rec = IPv4.IPv4_Options.TimestampRecord{
//           .timestamp = 999999,
//           .ip = ip0,
//       };
//
//       try ts_opt.add_ts_record(rec);
//
//       // check the first IP added matches the bytes of the IP we initialised
//       const ip_bytes = ts_opt.get_data()[IPv4.IPv4_Options.Timestamp.TLVHeaderLength .. IPv4.IPv4_Options.Timestamp.TLVHeaderLength + @sizeOf(IPv4.IPv4Address)];
//
//       try expect(std.mem.eql(u8, ip_bytes, &ip0.array));
//
//       // check the first timestamp added matches the bytes of the timestamp we initialised
//       const timestamp_bytes = ts_opt.get_data()[IPv4.IPv4_Options.Timestamp.TLVHeaderLength + @sizeOf(IPv4.IPv4Address) .. IPv4.IPv4_Options.Timestamp.TLVHeaderLength + @sizeOf(IPv4.IPv4Address) + @sizeOf(u32)];
//
//       try expect(std.mem.readInt(u32, timestamp_bytes[0..], .big) == rec.timestamp);
//
//       var records = try ts_opt.get_records(allocator) orelse {
//           try expect(false); // failed to get records
//           return;
//       };
//
//       var cur = records.first;
//       while (cur) |record| {
//           if (record.ip) |ipv4| {
//               const ipv4_str = try ipv4.to_string(allocator);
//               allocator.free(ipv4_str);
//           }
//           cur = record.next_record;
//       }
//
//       records.deinit(allocator);
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       var opt = IPv4.IPv4Option{ .timestamp = ts_opt };
//
//       try ipv4_layer.add_option(&opt);
//
//       try expect(ipv4_layer.get_data().len ==
//           IPv4.MinHeaderLength +
//               IPv4.IPv4_Options.Timestamp.TLVHeaderLength +
//               @sizeOf(IPv4.IPv4Address) +
//               @sizeOf(u32));
//   }
//
//   test "build router alert option" {
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       var ra_opt = try IPv4.IPv4_Options.RouterAlert.init(tlv_owner);
//
//       defer ra_opt.deinit();
//
//       try expect(ra_opt.get_data().len == 4);
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       var opt = IPv4.IPv4Option{ .router_alert = ra_opt };
//
//       try ipv4_layer.add_option(&opt);
//
//       try expect(ipv4_layer.get_data().len ==
//           IPv4.MinHeaderLength +
//               IPv4.IPv4_Options.RouterAlert.TLVHeaderLength);
//
//       try expect(ipv4_layer.get_immutable_header().get_length() == 24);
//
//       try expect(ipv4_layer.get_immutable_header().get_ihl() == 6);
//   }
//
//   test "build generic option" {
//       var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
//       defer _ = debug_allocator.detectLeaks();
//
//       const allocator = debug_allocator.allocator();
//
//       const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };
//       var go_opt = try IPv4.IPv4_Options.GenericOption.init(tlv_owner, IPv4.IPOptionType.MTUProbe);
//
//       defer go_opt.deinit();
//
//       try expect(go_opt.get_data().len == 2);
//
//       const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };
//
//       var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
//       defer ipv4_layer.deinit();
//
//       var opt = IPv4.IPv4Option{ .generic = go_opt };
//
//       try ipv4_layer.add_option(&opt);
//
//       try expect(ipv4_layer.get_immutable_header().get_length() == 24);
//
//       try expect(ipv4_layer.get_immutable_header().get_ihl() == 6);
//
//       const iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
//       print("{s}\n", .{iphdr_str});
//       allocator.free(iphdr_str);
//   }

test "build recr opt" {
    print("\nTESTING RR OPTION.\n", .{});
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    const tlv_owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    var rr = try IPv4.IPv4_Options.RecordRoute.init(tlv_owner);
    defer rr.deinit();

    try rr.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));
    try rr.add_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));
    try rr.add_ip(try IPv4.IPv4Address.init_from_string("172.78.9.3"));

    const ips = try rr.get_ip_list(allocator) orelse {
        try expect(false); // no ips found
        return;
    };

    try expect(rr.get_length() == ((@sizeOf(IPv4.IPv4Address) * 3) +
        IPv4.IPv4_Options.RecordRoute.TLVHeaderLength));

    for (ips) |ip| {
        const ip_str = try ip.to_string(allocator);
        //print("{s}\n", .{ip_str});
        allocator.free(ip_str);
    }

    defer allocator.free(ips);

    try expect(rr.get_ip_count() == 3);

    try expect(rr.get_ip_count() == ips.len);

    try rr.remove_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    const ip_list = try rr.get_ip_list(allocator) orelse {
        try expect(false); // ip list not found in RR option
        return;
    };

    defer allocator.free(ip_list);

    try expect(ip_list.len == 2);

    try expect(rr.get_length() == 11);

    for (ip_list) |ip| {
        const str = try ip.to_string(allocator);
        //print("{s}\n", .{str});
        allocator.free(str);
    }

    var opt = IPv4.IPv4Option{ .record_route = rr };

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);
    defer ipv4_layer.deinit();

    try ipv4_layer.add_option(&opt);

    print("ipv4 data: {x}\n", .{ipv4_layer.get_data()});

    if (ipv4_layer.check_pad()) |pad_len| {
        print("pad bytes: {}\n", .{pad_len});
    }

    var options = try ipv4_layer.get_options(allocator) orelse {
        try expect(false);
        return;
    };

    defer options.deinit(allocator);

    var cur = options.first;
    var count: usize = 0;
    while (cur) |option| {
        count += 1;
        const next = option.get_next();
        try expect(option.get_opt_type() == IPv4.IPOptionType.RecordRoute);
        cur = next;
    }

    try expect(count == 1);

    try expect(ipv4_layer.get_data().len == 32);

    try expect(ipv4_layer.get_immutable_header().dscp_ecn == 0);

    var rr_opt = ipv4_layer.get_first_op() orelse {
        try expect(false); // failed to get first opt
        return;
    };

    try expect(rr_opt.get_opt_type() == .RecordRoute);

    //print("rr opt data: ({}) {x}\n", .{ rr_opt.get_data().len, rr_opt.get_data() });

    try expect(rr_opt.get_length() == 11);

    try expect(rr_opt.get_data().len == 11);

    try rr_opt.record_route.remove_ip(try IPv4.IPv4Address.init_from_string("10.1.1.1"));

    try expect(rr_opt.get_length() == 7);

    try expect(rr_opt.get_data().len == 7);

    var iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
    //print("{s}\n", .{iphdr_str});
    allocator.free(iphdr_str);

    try expect(ipv4_layer.get_data().len == 28);

    try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("192.168.1.1"));

    try expect(rr_opt.get_length() == 11);

    try expect(rr_opt.get_data().len == 11);

    try expect(ipv4_layer.get_data().len == 32);

    try expect(ipv4_layer.get_immutable_header().get_length() == 32);

    try expect(ipv4_layer.get_immutable_header().get_ihl() == 8);

    try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("0.0.0.0"));

    try expect(rr_opt.record_route.get_length() == 15);

    try rr_opt.record_route.add_ip(try IPv4.IPv4Address.init_from_string("0.0.0.0"));

    try expect(rr_opt.record_route.get_length() == 19);

    //print("ipv4 data: {x}\n", .{ipv4_layer.get_data()});

    iphdr_str = try ipv4_layer.get_immutable_header().to_string(allocator);
    //print("{s}\n", .{iphdr_str});
    allocator.free(iphdr_str);

    if (ipv4_layer.check_pad()) |pad_len| {
        print("pad bytes: {}\n", .{pad_len});
    }
}
