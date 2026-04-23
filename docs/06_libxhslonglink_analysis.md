# libxhslonglink.so — Ghidra analysis

## Basic info
- Functions: 2728

## JNI exports (Java_com_xingin_*)

- `000558f8` Java_com_xingin_longlink_LongLink_start
- `00058018` Java_com_xingin_longlink_LongLink_stop
- `00058ac4` Java_com_xingin_longlink_LongLink_appStatusChange
- `00058c70` Java_com_xingin_longlink_LongLink_makeSureConnected
- `00058f00` Java_com_xingin_longlink_LongLink_manualPingPong
- `0005918c` Java_com_xingin_longlink_LongLink_networkStatusChange
- `00059370` Java_com_xingin_longlink_LongLink_updateNativeConfig
- `0005bf90` Java_com_xingin_longlink_LongLink_send
- `0005d9e0` Java_com_xingin_longlink_LongLink_initLongLink
- `0005dae0` Java_com_xingin_longlink_LongLink_shutdown
- `0005df18` Java_com_xingin_longlink_LongLink_restart
- `0005e068` Java_com_xingin_longlink_LongLink_changeServerAddress

Total: 12

## Crypto / signature strings

| Address | String |
|---|---|
| `00012199` | `_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc` |
| `000122c2` | `signal` |
| `00028872` | `"__OnSignalForeground` |
| `00029103` | `"SignallingKeeper` |
| `0002a15d` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002acc7` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002b928` | `"/builds/yryVZV8Z/0/android/redbuild/longlink/XYMars/mars/stn/src/signalling_kee...` |
| `0002b97e` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002bd12` | `"Signal Strength= %0, wifi:%1` |
| `0002c1f5` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<mar...` |
| `0002c673` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002d9a9` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002decf` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<mar...` |
| `0002e2bf` | `"SignallingKeeper messagequeue_id=%_, handler:(%_,%_)` |
| `0002e432` | `"static const char *mars_boost::detail::ctti<unsigned long long>::n() [T = unsig...` |
| `0002e9cd` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0002f86a` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `000308df` | `"sent signalling, period:%0` |
| `00030ce6` | `").  Contact the program author for an update.  If you compiled the program your...` |
| `00032643` | `"content_length_ != body.Lenght(), Head:%0, http dump:%1 \n headers size:%2` |
| `000326cd` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<mar...` |
| `000336ec` | `"error signal` |
| `00034a0b` | `"@%0, headers size:%_, ` |
| `00034b74` | `"__SendSignallingBuffer` |
| `00034f19` | `"HandleServerSignal` |
| `0003537d` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<boo...` |
| `00035dce` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `00035faf` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0003655d` | `"_signature != NULL` |
| `000370ce` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<int...` |
| `000373e6` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `00037836` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<mar...` |
| `0003802d` | `"handle signal: %_, biz: %_, room_id: %_, room_type: %_` |
| `0003815a` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `00038f8c` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::signals2::detai...` |
| `00039194` | `"@%0, status_code != 200, code:%1, http dump:%2 \n headers size:%3` |
| `00039aae` | `"0 <= _index && (unsigned int)_index < iarr_record_.size()` |
| `00039b84` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `00039f27` | `"stop signalling` |
| `0003a1fb` | `"recv error signal: %_` |
| `0003a5f7` | `"__OnSignalActive` |
| `0003ad5b` | `".  Please update your library.  If you compiled the program yourself, make sure...` |
| `0003afc9` | `"__SignalForeground` |
| `0003b2f7` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0003ba49` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0003c7e7` | `"static const char *mars_boost::detail::core_typeid_<MessageQueue::AsyncResult<u...` |
| `0003cad0` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::signals2::detai...` |
| `0003cfd2` | `"0 <= conn.Index() && (unsigned int)conn.Index() < _conn_profile.ip_items.size()` |
| `0003d144` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::signals2::detai...` |
| `0003da76` | `"recv server signal mid: %_` |
| `0003ddf5` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<boo...` |
| `0003e16d` | `"0 <= com_connect.Index() && (unsigned int)com_connect.Index() < ip_items.size()` |
| `0003e309` | `"static const char *mars_boost::detail::core_typeid_<mars_boost::_bi::bind_t<voi...` |
| `0003e6c8` | `"wrong header fields 128k buffer no found CRLFCRLF` |
| `0003fe78` | `"disconn_signal` |
| `00040028` | `"getSignal` |
| `00040180` | `"longlink.packet.SignalStreamData` |
| `00040590` | `"SignallingKeeper::__OnTimeOut` |
| `000405b0` | `"onEncrypt` |
| `00040748` | `"longlink.packet.SignalFrame` |
| `00040f34` | `"N10mars_boost8signals27signal4IvN4mars3stn10ErrCmdTypeEiRKNSt6__ndk112basic_str...` |
| `0004102a` | `"N10mars_boost8signals27signal5IvN4mars3stn10ErrCmdTypeEiRKNSt6__ndk112basic_str...` |
| `00041170` | `"N10mars_boost8signals26signalIFvNS_10shared_ptrIN4mars3stn7NetCoreEEEENS0_19opt...` |
| `00041227` | `"N10mars_boost8signals27signal1IvNS_10shared_ptrIN4mars3stn7NetCoreEEENS0_19opti...` |
| `000412e0` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `000413e7` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `000414df` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `000415c5` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `0004165c` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot1IviNS_8functionIFviEE...` |
| `000416b1` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00041768` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal4_implIvN4ma...` |
| `0004189d` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `000419e7` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal5_implIvN4ma...` |
| `00041b25` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00041c75` | `"N10mars_boost8signals26signalIFvN4mars3stn10ErrCmdTypeEiRKNSt6__ndk112basic_str...` |
| `00041d64` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal4_implIvN4ma...` |
| `00041e87` | `"N10mars_boost8signals26signalIFvN4mars3stn10ErrCmdTypeEiRKNSt6__ndk112basic_str...` |
| `00041f7c` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal5_implIvN4ma...` |
| `000420bc` | `"N10mars_boost8signals27signal2IvjRK10AutoBufferNS0_19optional_last_valueIvEEiNS...` |
| `00042161` | `"N10mars_boost8signals26signalIFvjRK10AutoBufferENS0_19optional_last_valueIvEEiN...` |
| `00042203` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00042300` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvjRK1...` |
| `000423e4` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvjRK1...` |
| `000424b6` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `0004256b` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot1IvRKN4mars3stn14Conne...` |
| `000425de` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `000426b3` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `00042752` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot3IvPKciiNS_8functionIF...` |
| `000427af` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00042a46` | `"N10mars_boost8signals27signal1IvRKN4mars3stn14ConnectProfileENS0_19optional_las...` |
| `00042af7` | `"N10mars_boost8signals27signal2IvNSt6__ndk112basic_stringIcNS2_11char_traitsIcEE...` |
| `00042bcb` | `"N10mars_boost8signals27signal1IvN4mars3stn8LongLink15TLongLinkStatusENS0_19opti...` |
| `00042d3c` | `"N10mars_boost8signals26signalIFvN4mars3stn8LongLink15TLongLinkStatusEENS0_19opt...` |
| `00042df3` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvN4ma...` |
| `00042ed9` | `"N10mars_boost8signals26signalIFvNSt6__ndk112basic_stringIcNS2_11char_traitsIcEE...` |
| `00042faa` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `000430d6` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvNSt6...` |
| `000431e9` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvNSt6...` |
| `000432ea` | `"N10mars_boost8signals26signalIFvRKN4mars3stn14ConnectProfileEENS0_19optional_la...` |
| `00043399` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `000434a3` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvRKN4...` |
| `00043593` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvRKN4...` |
| `000436e3` | `"N10mars_boost8signals26signalIFvNS_10shared_ptrIN4mars3stn16WeakNetworkLogicEEE...` |
| `000437a4` | `"N10mars_boost8signals27signal1IvNS_10shared_ptrIN4mars3stn16WeakNetworkLogicEEE...` |
| `00043867` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00043978` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `00043a7a` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `00043c33` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvN4ma...` |
| `00043d2b` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00043e3d` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `00043efa` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot1IvN4mars3stn8LongLink...` |
| `00043f75` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00044052` | `"N4mars3stn16SignallingKeeperE` |
| `000441f9` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `0004428f` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot0IvNS_8functionIFvvEEE...` |
| `000442e3` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `000443e0` | `"N10mars_boost8signals26signalIFvNS_10shared_ptrIN4mars3sdt7SdtCoreEEEENS0_19opt...` |
| `00044497` | `"N10mars_boost8signals27signal1IvNS_10shared_ptrIN4mars3sdt7SdtCoreEEENS0_19opti...` |
| `00044550` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00044657` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `0004474f` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `00044962` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `000449f9` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot1IvbNS_8functionIFvbEE...` |
| `00044a4e` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00044b46` | `"N10mars_boost8signals26signalIFvNS_10shared_ptrI11ActiveLogicEEENS0_19optional_...` |
| `00044bf7` | `"N10mars_boost8signals27signal1IvNS_10shared_ptrI11ActiveLogicEENS0_19optional_l...` |
| `00044caa` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00044dab` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `00044e9d` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvNS_1...` |
| `00045060` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `000450f7` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot1IvxNS_8functionIFvxEE...` |
| `0004514c` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00045203` | `"N10mars_boost8signals27signal0IvNS0_19optional_last_valueIvEEiNSt6__ndk14lessIi...` |
| `00045292` | `"N10mars_boost8signals27signal1IviNS0_19optional_last_valueIvEEiNSt6__ndk14lessI...` |
| `00045323` | `"N10mars_boost8signals27signal1IvbNS0_19optional_last_valueIvEEiNSt6__ndk14lessI...` |
| `000453b4` | `"N10mars_boost8signals27signal3IvPKciiNS0_19optional_last_valueIvEEiNSt6__ndk14l...` |
| `00045451` | `"N10mars_boost8signals27signal1IvxNS0_19optional_last_valueIvEEiNSt6__ndk14lessI...` |
| `000454e2` | `"N10mars_boost8signals26signalIFvvENS0_19optional_last_valueIvEEiNSt6__ndk14less...` |
| `00045572` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal0_implIvNS2_...` |
| `0004562e` | `"N10mars_boost8signals26signalIFviENS0_19optional_last_valueIvEEiNSt6__ndk14less...` |
| `000456bf` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIviNS2...` |
| `0004577d` | `"N10mars_boost8signals26signalIFvbENS0_19optional_last_valueIvEEiNSt6__ndk14less...` |
| `0004580e` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvbNS2...` |
| `000458cc` | `"N10mars_boost8signals26signalIFvPKciiENS0_19optional_last_valueIvEEiNSt6__ndk14...` |
| `00045965` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal3_implIvPKci...` |
| `00045a2f` | `"N10mars_boost8signals26signalIFvxENS0_19optional_last_valueIvEEiNSt6__ndk14less...` |
| `00045ac0` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvxNS2...` |
| `00045b7e` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal0_implIvNS2_...` |
| `00045c4c` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00045d37` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIviNS2...` |
| `00045e07` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00045ef3` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvbNS2...` |
| `00045fc3` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `000460af` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal3_implIvPKci...` |
| `0004618b` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `0004627f` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal1_implIvxNS2...` |
| `0004634f` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00046743` | `"N10mars_boost8signals26detail15connection_bodyINSt6__ndk14pairINS1_15slot_meta_...` |
| `000467fa` | `"N10mars_boost8signals26detail20connection_body_baseE` |
| `0004682f` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25slot2IvbRKN4mars4comm13che...` |
| `000468a4` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail15connection_bodyINS...` |
| `00046bc5` | `"N10mars_boost8signals27signal2IvbRKN4mars4comm13check_contentENS0_19optional_la...` |
| `00046c79` | `"N10mars_boost8signals211signal_baseE` |
| `00046c9e` | `"N10mars_boost8signals26detail19std_functional_baseE` |
| `00046cd2` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvbRKN...` |
| `00046dc5` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12grouped_listIiNSt6...` |
| `00046ed9` | `"N10mars_boost8signals26signalIFvbRKN4mars4comm13check_contentEENS0_19optional_l...` |
| `00046f8a` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals219optional_last_valueIvEEEE` |
| `00046fda` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals25mutexEEE` |
| `00047018` | `"N10mars_boost6detail17sp_counted_impl_pINS_8signals26detail12signal2_implIvbRKN...` |
| `00049bab` | `"N8longlink6packet11SignalFrameE` |
| `00049c05` | `"N8longlink6packet16SignalStreamDataE` |

Total interesting strings: 172

## Functions referencing crypto/signing strings

- `000cc634` FUN_000cc634 (sz=732)
- `000722c0` FUN_000722c0 (sz=17088)
- `00071fa8` _INIT_61 (sz=30)
- `0009635c` _INIT_82 (sz=30)
- `000cdd40` FUN_000cdd40 (sz=1380)
- `000ce388` FUN_000ce388 (sz=650)
- `000cd904` _INIT_106 (sz=30)
- `00115ba4` FUN_00115ba4 (sz=2608)
- `000a18a8` _INIT_85 (sz=30)
- `000c1334` _INIT_101 (sz=30)
- `00072134` _INIT_70 (sz=30)
- `000a1900` _INIT_87 (sz=30)
- `00072084` _INIT_66 (sz=30)
- `000720dc` _INIT_68 (sz=30)
- `0005302c` FUN_0005302c (sz=298)
- `000a192c` _INIT_88 (sz=30)
- `00072210` _INIT_75 (sz=30)
- `000c122c` _INIT_95 (sz=30)
- `000c138c` _INIT_103 (sz=30)
- `0011c938` FUN_0011c938 (sz=276)
- `00055140` JNI_OnLoad (sz=1684)
- `0011ca90` FUN_0011ca90 (sz=282)
- `0011b338` FUN_0011b338 (sz=572)
- `0011bf10` FUN_0011bf10 (sz=722)
- `00071f50` _INIT_59 (sz=30)
- `00072294` _INIT_78 (sz=30)
- `000ad244` _INIT_91 (sz=30)
- `00071f7c` _INIT_60 (sz=30)
- `000721b8` _INIT_73 (sz=30)
- `000933c4` FUN_000933c4 (sz=7858)
- `000c1284` _INIT_97 (sz=30)
- `000cc328` FUN_000cc328 (sz=732)
- `000768f8` FUN_000768f8 (sz=748)
- `000c1360` _INIT_102 (sz=30)
- `00072268` _INIT_77 (sz=30)
- `00111b24` _INIT_131 (sz=30)
- `0007218c` _INIT_72 (sz=30)
- `000c12dc` _INIT_99 (sz=30)
- `00072160` _INIT_71 (sz=30)
- `000ae308` FUN_000ae308 (sz=5236)
- `000c1258` _INIT_96 (sz=30)
- `000edba4` FUN_000edba4 (sz=5912)
- `0015e334` FUN_0015e334 (sz=2982)
- `000616c4` _INIT_43 (sz=2018)
- `001383b0` FUN_001383b0 (sz=48)
- `00061ffc` _INIT_45 (sz=2160)
- `0013893c` FUN_0013893c (sz=50)

## Top decompiled functions

### FUN_000cc634 @ `000cc634` (732 bytes)

```c

void FUN_000cc634(int param_1)

{
  byte bVar1;
  bool bVar2;
  char cVar3;
  undefined4 uVar4;
  ulonglong *puVar5;
  byte *pbVar6;
  int *piVar7;
  char *__s1;
  int *piVar8;
  int iVar9;
  int *piVar10;
  undefined4 uVar11;
  void *pvVar12;
  byte local_9c [8];
  void *local_94;
  ulonglong local_90;
  void *local_88;
  undefined4 local_80;
  int *local_7c;
  int *local_78;
  undefined4 local_70;
  undefined4 local_6c;
  byte local_68;
  undefined2 local_67;
  byte local_65;
  undefined4 local_64;
  void *local_60;
  undefined8 local_58;
  undefined4 uStack_50;
  undefined4 local_4c;
  undefined4 *local_48;
  int local_44 [6];
  undefined2 local_2c;
  byte local_2a;
  int local_28;
  
  local_28 = **(int **)(DAT_000cc910 + 0xcc646);
  uVar4 = *(undefined4 *)(param_1 + 0x10);
  FUN_000f0554(local_9c,DAT_000cc914 + 0xcc658);
  puVar5 = (ulonglong *)FUN_00051f38(local_9c,DAT_000cc918 + 0xcc662);
  local_90 = *puVar5;
  local_88 = *(void **)(puVar5 + 1);
  iVar9 = DAT_000cc91c + 0xcc678;
  *(undefined4 *)puVar5 = 0;
  *(undefined4 *)((int)puVar5 + 4) = 0;
  *(undefined4 *)(puVar5 + 1) = 0;
  pbVar6 = (byte *)FUN_00051f38(&local_90,iVar9);
  local_2a = pbVar6[3];
  local_2c = *(undefined2 *)(pbVar6 + 1);
  uVar11 = *(undefined4 *)(pbVar6 + 4);
  pvVar12 = *(void **)(pbVar6 + 8);
  bVar1 = *pbVar6;
  pbVar6[0] = 0;
  pbVar6[1] = 0;
  pbVar6[2] = 0;
  pbVar6[3] = 0;
  pbVar6[4] = 0;
  pbVar6[5] = 0;
  pbVar6[6] = 0;
  pbVar6[7] = 0;
  pbVar6[8] = 0;
  pbVar6[9] = 0;
  pbVar6[10] = 0;
  pbVar6[0xb] = 0;
  local_80 = 0;
  piVar7 = operator_new(0x24);
  iVar9 = DAT_000cc920;
  piVar7[3] = 0;
  piVar7[5] = 0;
  *piVar7 = iVar9 + 0xcc6ba;
  piVar10 = piVar7 + 2;
  *piVar10 = 1;
  piVar8 = piVar7 + 1;
  *piVar8 = 1;
  *(undefined1 *)(piVar7 + 4) = 1;
  do {
    ExclusiveAccess(piVar8);
    bVar2 = (bool)hasExclusiveAccess(piVar8);
  } while (!bVar2);
  *piVar8 = *piVar8 + 1;
  DataMemoryBarrier(0x1b);
  do {
    ExclusiveAccess(piVar8);
    iVar9 = *piVar8;
    bVar2 = (bool)hasExclusiveAccess(piVar8);
  } while (!bVar2);
  *piVar8 = iVar9 + -1;
  DataMemoryBarrier(0x1b);
  if (iVar9 == 1) {
    (**(code **)(*piVar7 + 8))(piVar7);
    DataMemoryBarrier(0x1b);
    do {
      ExclusiveAccess(piVar10);
      iVar9 = *piVar10;
      bVar2 = (bool)hasExclusiveAccess(piVar10);
    } while (!bVar2);
    *piVar10 = iVar9 + -1;
    DataMemoryBarrier(0x1b);
    if (iVar9 == 1) {
      (**(code **)(*piVar7 + 0xc))(piVar7);
    }
  }
  local_7c = operator_new(0xc);
  iVar9 = DAT_000cc924;
  local_7c[2] = (int)piVar7;
  *local_7c = iVar9 + 0xcc730;
  local_7c[1] = (int)(piVar7 + 5);
  do {
    ExclusiveAccess(piVar8);
    bVar2 = (bool)hasExclusiveAccess(piVar8);
  } while (!bVar2);
  *piVar8 = *piVar8 + 1;
  DataMemoryBarrier(0x1b);
  do {
    ExclusiveAccess(piVar8);
    iVar9 = *piVar8;
    bVar2 = (bool)hasExclusiveAccess(piVar8);
  } while (!bVar2);
  *piVar8 = iVar9 + -1;
  DataMemoryBarrier(0x1b);
  if (iVar9 == 1) {
    (**(code **)(*piVar7 + 8))(piVar7);
    DataMemoryBarrier(0x1b);
    do {
      ExclusiveAccess(piVar10);
      iVar9 = *piVar10;
      bVar2 = (bool)hasExclusiveAccess(piVar10);
    } while (!bVar2);
    *piVar10 = iVar9 + -1;
    DataMemoryBarrier(0x1b);
    if (iVar9 == 1) {
      (**(code **)(*piVar7 + 0xc))(piVar7);
    }
  }
  cVar3 = bVar1 * -0x80;
  local_70 = 600000;
  local_6c = 0;
  local_78 = (int *)0x0;
  if (cVar3 == '\0') {
    local_67 = local_2c;
    local_65 = local_2a;
    local_68 = bVar1;
    local_64 = uVar11;
    local_60 = pvVar12;
  }
  else {
    FUN_000569fc(&local_68,pvVar12,uVar11);
  }
  local_58 = FUN_000f0620();
  piVar10 = local_7c;
  local_4c = 0;
  uStack_50 = 0;
  if (local_7c == (int *)0x0) {
    __s1 = (char *)(DAT_000cc928 + 0xcc817);
  }
  else {
    __s1 = (char *)(**(code **)(*local_7c + 8))(local_7c,*(code **)(*local_7c + 8),0,&local_4c);
  }
  if ((__s1 != (char *)(DAT_000cc92c + 0xcc81d)) &&
     (iVar9 = strcmp(__s1,(char *)(DAT_000cc92c + 0xcc81d)), iVar9 != 0)) {
    local_48 = (undefined4 *)(DAT_000cc93c + 0xcc90a);
    FUN_000ec810((exception *)&local_48);
                    /* WARNING: Subroutine does not return */
    std::exception::~exception((exception *)&local_48);
  }
  iVar9 = piVar10[1];
  piVar10 = (int *)piVar10[2];
  if (piVar10 != (int *)0x0) {
    piVar8 = piVar10 + 1;
    do {
      ExclusiveAccess(piVar8);
      bVar2 = (bool)hasExclusiveAccess(piVar8);
    } while (!bVar2);
    *piVar8 = *piVar8 + 1;
  }
  local_48 = (undefined4 *)(DAT_000cc930 + 0xcc812U | 1);
  local_44[0] = param_1;
  FUN_00063a14(&local_48,iVar9);
  if (((local_48 != (undefined4 *)0x0) && (((uint)local_48 & 1) == 0)) &&
     ((code *)*local_48 != (code *)0x0)) {
    (*(code *)*local_48)(local_44,local_44,2);
  }
  if (piVar10 != (int *)0x0) {
    piVar8 = piVar10 + 1;
    DataMemoryBarrier(0x1b);
    do {
      ExclusiveAccess(piVar8);
      iVar9 = *piVar8;
      bVar2 = (bool)hasExclusiveAccess(piVar8);
    } while (!bVar2);
    *piVar8 = iVar9 + -1;
    DataMemoryBarrier(0x1b);
    if (iVar9 == 1) {
      piVar8 = piVar10 + 2;
      (**(code **)(*piVar10 + 8))(piVar10);
      DataMemoryBarrier(0x1b);
      do {
        ExclusiveAccess(piVar8);
        iVar9 = *piVar8;
        bVar2 = (bool)hasExclusiveAccess(piVar8);
      } while (!bVar2);
      *piVar8 = iVar9 + -1;
      DataMemoryBarrier(0x1b);
      if (iVar9 == 1) {
        (**(code **)(*piVar10 + 0xc))(piVar10);
      }
    }
  }
  FUN_00106f20(&local_48,uVar4,&local_80,DAT_000cc934 + 0xcc8ba);
  if ((local_68 & 1) != 0) {
    operator_delete(local_60);
  }
  if (local_78 != (int *)0x0) {
    (**(code **)(*local_78 + 4))();
  }
  if (local_7c != (int *)0x0) {
    (**(code **)(*local_7c + 4))();
  }
  if (cVar3 != '\0') {
    operator_delete(pvVar12);
  }
  if ((local_90 & 1) != 0) {
    operator_delete(local_88);
  }
  if ((local_9c[0] & 1) != 0) {
    operator_delete(local_94);
  }
  if (**(int **)(DAT_000cc938 + 0xcc8e8) == local_28) {
    return;
  }
                    /* WARNING: Sub
// ... [truncated]

```

### FUN_000722c0 @ `000722c0` (17088 bytes)

```c

/* WARNING: Type propagation algorithm not settling */

void FUN_000722c0(uint ******param_1)

{
  char cVar1;
  byte bVar2;
  undefined2 uVar3;
  longlong lVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  uint ****ppppuVar8;
  uint ****ppppuVar9;
  char cVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  basic_string bVar13;
  uint ****ppppuVar14;
  uint **ppuVar15;
  uint ***pppuVar16;
  uint ***pppuVar17;
  uint ****ppppuVar18;
  uint ******ppppppuVar19;
  pthread_mutex_t *__mutex;
  undefined8 *puVar20;
  int iVar21;
  int *piVar22;
  uint uVar23;
  int *piVar24;
  int iVar25;
  int iVar26;
  uint *****pppppuVar27;
  uint uVar28;
  uint ******ppppppuVar29;
  byte *pbVar30;
  int iVar31;
  char *pcVar32;
  uint uVar33;
  uint ****ppppuVar34;
  undefined1 *puVar35;
  byte *pbVar36;
  ulonglong *puVar37;
  uint *puVar38;
  int *piVar39;
  uint *puVar40;
  uint *puVar41;
  undefined1 uVar42;
  byte bVar43;
  uint *****pppppuVar44;
  uint ******ppppppuVar45;
  uint ******ppppppuVar46;
  int iVar47;
  uint *****pppppuVar48;
  uint ******ppppppuVar49;
  undefined1 *puVar50;
  undefined4 uVar51;
  undefined4 *puVar52;
  uint *puVar53;
  uint *puVar54;
  uint *****pppppuVar55;
  uint ****ppppuVar56;
  uint uVar57;
  uint ******ppppppuVar58;
  uint *puVar59;
  uint *****pppppuVar60;
  undefined1 *puVar61;
  undefined1 *puVar62;
  uint **ppuVar63;
  uint ******ppppppuVar64;
  uint uVar65;
  int iVar66;
  uint *******pppppppuVar67;
  int *piVar68;
  uint ***pppuVar69;
  size_t sVar70;
  uint *puVar71;
  int iVar72;
  uint uVar73;
  int iVar74;
  void *pvVar75;
  uint *puVar76;
  uint *******pppppppuVar77;
  uint *****pppppuVar78;
  int iVar79;
  uint *puVar80;
  bool bVar81;
  undefined4 uVar82;
  undefined4 uVar83;
  undefined4 uVar84;
  undefined8 uVar85;
  undefined1 auStack_704 [4];
  int *local_700;
  undefined1 auStack_6fc [4];
  int *local_6f8;
  undefined1 auStack_6f4 [4];
  int *local_6f0;
  undefined1 auStack_6ec [4];
  int *local_6e8;
  uint ****local_6e4;
  int *local_6e0;
  void *local_6dc;
  byte local_6d8;
  byte bStack_6d7;
  undefined2 uStack_6d6;
  undefined4 local_6d4;
  uint *****local_6d0;
  undefined2 local_6bc;
  char local_6ba;
  undefined8 local_6b8;
  undefined4 local_6b0;
  uint local_6ac;
  void *local_6a8;
  undefined8 local_6a0;
  undefined8 uStack_698;
  undefined8 local_690;
  undefined1 auStack_688 [8];
  undefined8 uStack_680;
  undefined8 uStack_678;
  undefined8 local_670;
  undefined4 local_668;
  undefined4 local_664;
  undefined1 auStack_660 [127];
  undefined1 local_5e1;
  undefined8 local_5e0;
  undefined8 uStack_5d8;
  undefined4 local_5d0;
  undefined8 local_5c8;
  undefined8 local_5c0;
  undefined8 local_5b8;
  undefined4 local_5b0;
  undefined1 auStack_5ac [4];
  undefined8 uStack_5a8;
  undefined8 local_5a0;
  undefined8 local_598;
  undefined4 local_590;
  undefined4 local_58c;
  undefined1 auStack_588 [127];
  undefined1 local_509;
  undefined8 local_508;
  undefined8 uStack_500;
  undefined4 local_4f8;
  uint *******local_4c8;
  uint ******ppppppuStack_4c4;
  uint *****local_4c0;
  uint ******ppppppuStack_4bc;
  uint ****local_4b8;
  void *pvStack_4b4;
  undefined8 local_4b0;
  undefined8 local_4a8;
  undefined8 local_4a0;
  undefined4 local_498;
  undefined4 uStack_494;
  undefined4 uStack_490;
  undefined4 uStack_48c;
  undefined4 uStack_488;
  undefined1 local_484;
  int local_480;
  undefined4 local_47c;
  uint local_478;
  uint *******local_474;
  int local_470;
  pthread_mutex_t *local_46c;
  undefined4 uStack_c8;
  undefined4 local_c4;
  void *pvStack_c0;
  uint ******local_bc;
  undefined8 uStack_b8;
  undefined8 uStack_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 local_98;
  int local_90;
  undefined4 uStack_8c;
  undefined8 local_80;
  undefined4 *puStack_78;
  undefined4 local_74;
  uint uStack_70;
  ulonglong uStack_6c;
  undefined8 local_64;
  undefined8 uStack_5c;
  undefined8 local_54;
  undefined8 uStack_4c;
  undefined4 local_44;
  int iStack_40;
  
  pppppuVar44 = (uint *****)(DAT_00072660 + 0x722e8);
  iStack_40 = **(int **)(DAT_00072664 + 0x722e2);
  pppppuVar55 = (uint *****)(DAT_0007265c + 0x722e6);
  param_1[5] = (uint *****)0x0;
  param_1[9] = pppppuVar55;
  *param_1 = pppppuVar44;
  param_1[1] = (uint *****)0x0;
  pppppuVar44 = operator_new(0x14);
  ppppuVar14 = operator_new(0x10);
  ppppppuStack_4bc = (uint ******)&local_4b8;
  local_4b8 = (uint ****)0x0;
  pvStack_4b4 = (void *)0x0;
  local_4c0 = (uint *****)0x0;
  local_4c8 = (uint *******)&local_4c8;
  ppppppuStack_4c4 = (uint ******)&local_4c8;
  ppuVar15 = operator_new(0x20);
  pppuVar16 = (uint ***)FUN_0007dc54(ppuVar15,&local_4c8);
  *ppppuVar14 = pppuVar16;
  pppuVar16 = operator_new(0x10);
  iVar47 = DAT_00072668;
  pppuVar16[2] = (uint **)0x1;
  pppuVar16[3] = ppuVar15;
  ppppuVar14[1] = pppuVar16;
  *pppuVar16 = (uint **)(iVar47 + 0x72348);
  pppuVar16[1] = (uint **)0x1;
  pppuVar16 = operator_new(1);
  ppppuVar14[2] = pppuVar16;
  pppuVar17 = operator_new(0x10);
  iVar47 = DAT_0007266c;
  pppuVar17[2] = (uint **)0x1;
  pppuVar17[3] = (uint **)pppuVar16;
  ppppuVar14[3] = pppuVar17;
  *pppuVar17 = (uint **)(iVar47 + 0x72368);
  pppuVar17[1] = (uint **)0x1;
  *pppppuVar44 = ppppuVar14;
  ppppuVar18 = operator_new(0x10);
  iVar47 = DAT_00072670;
  ppppuVar18[2] = (uint ***)0x1;
  ppppuVar18[3] = (uint ***)ppppuVar14;
  *ppppuVar18 = (uint ***)(iVar47 + 0x72380);
  ppppuVar18[1] = (uint ***)0x1;
  pppppuVar44[1] = ppppuVar18;
  FUN_0007e052(local_4b8);
  if (local_4c0 != (uint *****)0x0) {
    ppppppuVar45 = (uint ******)*ppppppuStack_4c4;
    ppppppuVar19 = local_4c8[1];
    ppppppuVar45[1] = (uint *****)ppppppuVar19;
    *ppppppuVar19 = (uint *****)ppppppuVar45;
    local_4c0 = (uint *****)0x0;
    pppppppuVar67 = (uint *******)ppppppuStack_4c4;
    if ((uint ********)ppppppuStack_4c4 != &local_4c8) {
      do {
        pppppppuVar77 = (uint *******)pppppppuVar67[1];
        ppppppuVar19 = pppppppuVar67[3];
        if (ppppp
// ... [truncated]

```

### _INIT_61 @ `00071fa8` (30 bytes)

```c

void _INIT_61(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = DAT_00071fd0;
  if ((*(byte *)(DAT_00071fc8 + 0x71fae) & 1) != 0) {
    return;
  }
  puVar2 = (undefined4 *)(DAT_00071fcc + 0x71fbe);
  *(byte *)(DAT_00071fc8 + 0x71fae) = 1;
  *(int *)*puVar2 = iVar1 + 0x71fc2;
  return;
}


```

### _INIT_82 @ `0009635c` (30 bytes)

```c

void _INIT_82(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = DAT_00096384;
  if ((*(byte *)(DAT_0009637c + 0x96362) & 1) != 0) {
    return;
  }
  puVar2 = (undefined4 *)(DAT_00096380 + 0x96372);
  *(byte *)(DAT_0009637c + 0x96362) = 1;
  *(int *)*puVar2 = iVar1 + 0x96376;
  return;
}


```

### FUN_000cdd40 @ `000cdd40` (1380 bytes)

```c

void FUN_000cdd40(int param_1)

{
  int *piVar1;
  undefined1 uVar2;
  byte bVar3;
  char cVar4;
  int iVar5;
  int *piVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  size_t sVar9;
  int *piVar10;
  char *__s2;
  uint uVar11;
  uint uVar12;
  char *pcVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  int iVar16;
  size_t sVar17;
  undefined4 *unaff_r9;
  int iVar18;
  bool bVar19;
  undefined4 uVar20;
  undefined4 **ppuVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  int local_2a8 [2];
  undefined4 local_2a0;
  int iStack_29c;
  int local_298;
  int iStack_294;
  undefined4 uStack_290;
  undefined4 local_28c;
  undefined8 local_288;
  undefined8 local_280;
  undefined8 local_278;
  undefined4 local_270;
  undefined4 local_26c;
  undefined5 uStack_268;
  undefined8 uStack_263;
  undefined4 local_258;
  undefined4 local_254;
  undefined1 local_250;
  byte local_220;
  char local_21f [3];
  size_t local_21c;
  void *local_218;
  ushort local_214;
  undefined4 *local_180;
  undefined1 auStack_17c [4];
  uint local_178;
  int iStack_174;
  undefined4 uStack_170;
  undefined4 local_16c;
  undefined8 local_168;
  undefined8 local_160;
  undefined8 local_158;
  undefined4 local_150;
  undefined4 local_14c;
  undefined5 uStack_148;
  undefined8 uStack_143;
  int local_138;
  undefined4 local_134;
  undefined1 local_130;
  undefined4 **local_80;
  undefined8 uStack_7c;
  undefined8 uStack_74;
  undefined8 local_6c;
  undefined8 uStack_64;
  undefined8 local_5c;
  undefined4 uStack_54;
  undefined4 local_50;
  undefined4 uStack_4c;
  undefined8 uStack_48;
  int local_3c;
  
  iVar18 = *(int *)(DAT_000ce01c + 0xcdd5a);
  local_3c = **(int **)(DAT_000ce2d4 + 0xcdd68);
  if (iVar18 != 0) {
    iVar5 = __xlogger_IsEnabledFor_impl(1);
    if (iVar5 != 0) {
      local_298 = DAT_000ce020 + 0xcdd94;
      local_288 = 0;
      iStack_29c = DAT_000ce024 + 0xcdd9a;
      iStack_294 = DAT_000ce028 + 0xcdda0;
      local_2a0 = 1;
      uStack_290 = 0x93;
      local_278 = 0xffffffffffffffff;
      local_280 = 0xffffffffffffffff;
      local_270 = 0xffffffff;
      uStack_268 = 0;
      uStack_263 = 0;
      local_258 = 0;
      local_250 = 0;
      local_254 = 0;
      local_28c = 0;
      local_26c = 0xffffffff;
      FUN_0005091c(&uStack_268,0x200);
      local_178 = local_178 & 0xffffff00;
      local_180 = (undefined4 *)0x0;
      auStack_17c = (undefined1  [4])0x35303030;
      local_80 = &local_180;
      local_180 = (undefined4 *)auStack_17c;
      puVar7 = (undefined4 *)(auStack_17c + 3);
      puVar14 = local_180;
      do {
        uVar2 = *(undefined1 *)puVar7;
        puVar8 = (undefined4 *)((int)puVar7 + -1);
        *(undefined1 *)puVar7 = *(undefined1 *)puVar14;
        puVar15 = (undefined4 *)((int)puVar14 + 1);
        *(undefined1 *)puVar14 = uVar2;
        puVar7 = puVar8;
        puVar14 = puVar15;
      } while (puVar15 < puVar8);
      uStack_7c = 0;
      uStack_74 = 0;
      local_6c = 0;
      uStack_64 = 0;
      local_5c = 0;
      uStack_54 = 0;
      local_50 = 0;
      uStack_4c = 0;
      uStack_48 = 0;
      FUN_00068440(&local_2a0,DAT_000ce02c + 0xcde1c);
      FUN_00056600(&local_2a0);
    }
    if ((iVar18 != 0) && (iVar5 = __xlogger_IsEnabledFor_impl(2), iVar5 != 0)) {
      uVar20 = 0;
      uVar22 = 0;
      uVar23 = 0;
      uVar24 = 0;
      unaff_r9 = &local_2a0;
      local_298 = DAT_000ce030 + 0xcde60;
      local_288 = 0;
      iStack_29c = DAT_000ce034 + 0xcde66;
      iStack_294 = DAT_000ce038 + 0xcde6c;
      local_2a0 = 2;
      uStack_290 = 0x75;
      local_278 = 0xffffffffffffffff;
      local_280 = 0xffffffffffffffff;
      local_270 = 0xffffffff;
      uStack_268 = 0;
      uStack_263 = 0;
      local_258 = 0;
      local_250 = 0;
      local_254 = 0;
      local_28c = 0;
      local_26c = 0xffffffff;
      FUN_0005091c(&uStack_268,0x200);
      auStack_17c = (undefined1  [4])((uint)auStack_17c & 0xffffff00);
      local_180 = (undefined4 *)(DAT_000ce040 + 0xcdeb6);
      if (*(char *)(param_1 + 0xdc) == '\0') {
        local_180 = (undefined4 *)(DAT_000ce03c + 0xcdeb4);
      }
      uStack_7c = CONCAT44(uVar22,uVar20);
      uStack_74 = CONCAT44(uVar24,uVar23);
      local_6c = CONCAT44(uVar22,uVar20);
      uStack_64 = CONCAT44(uVar24,uVar23);
      local_5c = CONCAT44(uVar22,uVar20);
      uStack_48 = CONCAT44(uVar24,uVar23);
      local_80 = &local_180;
      uStack_54 = uVar23;
      local_50 = uVar20;
      uStack_4c = uVar22;
      FUN_00068440(unaff_r9,DAT_000ce044 + 0xcdecc);
      FUN_00056600(unaff_r9);
    }
  }
  if (*(char *)(param_1 + 0xdc) == '\0') {
    uVar11 = *(uint *)(param_1 + 4);
    iVar5 = DAT_000ce048 + 0xcdf2c;
    if (uVar11 == 0) {
      iVar5 = 0;
    }
    if (iVar5 != 0) {
      if (uVar11 == 0) {
        std::runtime_error::runtime_error
                  ((runtime_error *)local_2a8,(char *)(DAT_000ce308 + 0xcdf40));
        local_2a8[0] = DAT_000ce30c + 0xcdf54;
        if ((iVar18 != 0) && (iVar18 = __xlogger_IsEnabledFor_impl(5), iVar18 != 0)) {
          uVar20 = 0;
          uVar22 = 0;
          uVar23 = 0;
          uVar24 = 0;
          local_298 = DAT_000ce310 + 0xcdf78;
          local_288 = 0;
          iStack_29c = DAT_000ce314 + 0xcdf7e;
          local_2a0 = 5;
          iStack_294 = DAT_000ce318 + 0xcdf92;
          uStack_290 = 0x1b;
          local_278 = 0xffffffffffffffff;
          local_280 = 0xffffffffffffffff;
          local_270 = 0xffffffff;
          uStack_268 = 0;
          uStack_263 = 0;
          local_258 = 0;
          local_250 = 0;
          local_254 = 0;
          local_28c = 0;
          local_26c = 0xffffffff;
          FUN_0005091c(&uStack_268,0x200);
          local_180 = (undefined4 *)(**(code **)(local_2a8[0] + 8))(local_2a8);
          uStack_7c = CONCAT44(uVar22,uVar20);
          uStack_74 = CONCAT44(uVar24,uVar23);
          local_6c = CONCAT44(uVar22,uVar20);
          uStack_64 = CONCAT44(uVar24,uVar23);
          local_5c = CONCAT44(uVar22,uVar2
// ... [truncated]

```

### FUN_000ce388 @ `000ce388` (650 bytes)

```c

void FUN_000ce388(int *param_1)

{
  int iVar1;
  void *pvVar2;
  undefined4 *puVar3;
  int *piVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  bool bVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 local_d0;
  int iStack_cc;
  int local_c8;
  int iStack_c4;
  undefined4 uStack_c0;
  undefined4 local_bc;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined5 uStack_98;
  undefined8 uStack_93;
  undefined4 local_88;
  undefined4 local_84;
  undefined1 local_80;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int local_34;
  
  iVar1 = *(int *)(DAT_000ce614 + 0xce3a2);
  local_34 = **(int **)(DAT_000ce61c + 0xce3a6);
  *param_1 = DAT_000ce618 + 0xce3ac;
  if ((iVar1 != 0) && (iVar1 = __xlogger_IsEnabledFor_impl(2), iVar1 != 0)) {
    uVar9 = 0;
    uVar10 = 0;
    uVar11 = 0;
    uVar12 = 0;
    local_c8 = DAT_000ce620 + 0xce3da;
    local_b8 = 0;
    iStack_cc = DAT_000ce624 + 0xce3e0;
    iStack_c4 = DAT_000ce628 + 0xce3e6;
    local_d0 = 2;
    local_88 = 0;
    local_80 = 0;
    local_84 = 0;
    local_bc = 0;
    uStack_c0 = 0x6b;
    local_a8 = 0xffffffffffffffff;
    local_b0 = 0xffffffffffffffff;
    local_a0 = 0xffffffff;
    uStack_98 = 0;
    uStack_93 = 0;
    local_9c = 0xffffffff;
    FUN_0005091c(&uStack_98,0x200);
    local_78 = uVar9;
    uStack_74 = uVar10;
    uStack_70 = uVar11;
    uStack_6c = uVar12;
    local_68 = uVar9;
    uStack_64 = uVar10;
    uStack_60 = uVar11;
    uStack_5c = uVar12;
    local_58 = uVar9;
    uStack_54 = uVar10;
    uStack_50 = uVar11;
    uStack_4c = uVar12;
    local_48 = uVar9;
    uStack_44 = uVar10;
    uStack_40 = uVar11;
    uStack_3c = uVar12;
    FUN_00068440(&local_d0,DAT_000ce62c + 0xce42c);
    FUN_00056600(&local_d0);
  }
  if ((char)param_1[8] != '\0') {
    uVar6 = *(uint *)(DAT_000ce630 + 0xce458);
    uVar5 = param_1[10] ^ uVar6 | *(uint *)(DAT_000ce630 + 0xce45c) ^ param_1[0xb];
    bVar8 = uVar5 == 0;
    if (bVar8) {
      uVar5 = *(uint *)(DAT_000ce630 + 0xce460);
      uVar6 = param_1[0xc];
    }
    if ((!bVar8 || uVar6 != uVar5) || (param_1[0xe] != *(int *)(DAT_000ce630 + 0xce468))) {
      *(undefined1 *)(param_1 + 8) = 0;
      FUN_0010bbf0();
    }
  }
  if ((param_1[0x30] != 0) && (*(char *)(*(int *)(param_1[0x30] + 4) + 0xd) == '\0')) {
    param_1[0x1a] = 0;
    FUN_00110318(param_1 + 0x1b);
    FUN_000ad0a8(param_1[0x30]);
  }
  FUN_00110318(param_1 + 0x1b);
  if ((int *)param_1[0x30] != (int *)0x0) {
    (**(code **)(*(int *)param_1[0x30] + 4))();
  }
  param_1[0x30] = 0;
  if (param_1[0x33] != 0) {
    piVar7 = (int *)param_1[0x32];
    iVar1 = *piVar7;
    param_1[0x33] = 0;
    piVar4 = *(int **)(param_1[0x31] + 4);
    *(int **)(iVar1 + 4) = piVar4;
    *piVar4 = iVar1;
    while (piVar7 != param_1 + 0x31) {
      piVar4 = (int *)piVar7[1];
      if ((void *)piVar7[2] != (void *)0x0) {
        free((void *)piVar7[2]);
      }
      operator_delete(piVar7);
      piVar7 = piVar4;
    }
  }
  if (param_1[0x15] != -1) {
    close(param_1[0x15]);
  }
  FUN_000688ec(param_1 + 0x34);
  if (param_1[0x33] != 0) {
    piVar7 = (int *)param_1[0x32];
    iVar1 = *piVar7;
    param_1[0x33] = 0;
    piVar4 = *(int **)(param_1[0x31] + 4);
    *(int **)(iVar1 + 4) = piVar4;
    *piVar4 = iVar1;
    while (piVar7 != param_1 + 0x31) {
      piVar4 = (int *)piVar7[1];
      if ((void *)piVar7[2] != (void *)0x0) {
        free((void *)piVar7[2]);
      }
      operator_delete(piVar7);
      piVar7 = piVar4;
    }
  }
  pvVar2 = (void *)param_1[0x2b];
  iVar1 = DAT_000ce634 + 0xce54e;
  param_1[0x21] = DAT_000ce638 + 0xce556;
  param_1[0x22] = iVar1;
  if (pvVar2 != (void *)0x0) {
    param_1[0x2c] = (int)pvVar2;
    operator_delete(pvVar2);
  }
  FUN_00110b1c(param_1[0x29]);
  pvVar2 = (void *)param_1[0x25];
  if (pvVar2 != (void *)0x0) {
    param_1[0x26] = (int)pvVar2;
    operator_delete(pvVar2);
  }
  *(undefined1 *)((int)param_1 + 0x75) = 1;
  if (-1 < param_1[0x1c]) {
    close(param_1[0x1c]);
  }
  iVar1 = param_1[0x1b];
  if (-1 < iVar1) {
    close(iVar1);
  }
  param_1[0x1b] = -1;
  param_1[0x1c] = -1;
  FUN_000688ec(param_1 + 0x1e);
  if ((*(byte *)(param_1 + 0x11) & 1) != 0) {
    operator_delete((void *)param_1[0x13]);
  }
  FUN_00108f44(param_1[5]);
  FUN_0010be58(param_1[5]);
  if ((void *)param_1[5] != (void *)0x0) {
    operator_delete((void *)param_1[5]);
  }
  puVar3 = (undefined4 *)param_1[1];
  if (puVar3 != (undefined4 *)0x0) {
    if ((((uint)puVar3 & 1) == 0) && ((code *)*puVar3 != (code *)0x0)) {
      (*(code *)*puVar3)(param_1 + 2,param_1 + 2,2);
    }
    param_1[1] = 0;
  }
  if (**(int **)(DAT_000ce63c + 0xce5f8) == local_34) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(local_34);
}


```

### _INIT_106 @ `000cd904` (30 bytes)

```c

void _INIT_106(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = DAT_000cd92c;
  if ((*(byte *)(DAT_000cd924 + 0xcd90a) & 1) != 0) {
    return;
  }
  puVar2 = (undefined4 *)(DAT_000cd928 + 0xcd91a);
  *(byte *)(DAT_000cd924 + 0xcd90a) = 1;
  *(int *)*puVar2 = iVar1 + 0xcd91e;
  return;
}


```

### FUN_00115ba4 @ `00115ba4` (2608 bytes)

```c

void FUN_00115ba4(int param_1)

{
  int *piVar1;
  int *piVar2;
  undefined1 uVar3;
  bool bVar4;
  longlong lVar5;
  longlong lVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  char *__s1;
  void *pvVar10;
  int *piVar11;
  undefined4 *puVar12;
  undefined8 *puVar13;
  int *piVar14;
  int *piVar15;
  undefined4 uVar16;
  undefined8 *puVar17;
  undefined8 *puVar18;
  undefined8 *puVar19;
  char *__s1_00;
  int *piVar20;
  int iVar21;
  int iVar22;
  undefined8 uVar23;
  longlong lVar24;
  ulonglong local_610;
  void *local_608;
  ulonglong local_604;
  void *local_5fc;
  ulonglong local_5f8;
  void *local_5f0;
  undefined1 auStack_5e8 [4];
  int *local_5e4;
  int local_5d8;
  undefined1 local_5d4;
  undefined1 auStack_591 [5];
  undefined8 local_58c;
  int *local_584;
  undefined1 local_548 [8];
  longlong local_540;
  undefined8 uStack_538;
  undefined4 local_530;
  undefined1 auStack_52c [12];
  undefined8 local_520;
  undefined8 local_518;
  undefined4 local_510;
  undefined4 local_50c;
  undefined1 auStack_508 [127];
  undefined1 local_489;
  undefined8 local_488;
  undefined8 uStack_480;
  undefined4 local_478;
  undefined8 *local_470;
  undefined8 local_46c;
  int *local_464;
  undefined4 local_460;
  undefined4 local_45c;
  ulonglong local_458;
  undefined8 local_450;
  undefined8 local_448;
  undefined4 local_440;
  undefined4 local_43c;
  undefined5 uStack_438;
  undefined8 uStack_433;
  undefined4 local_428;
  undefined4 local_424;
  undefined1 local_420;
  int *piStack_70;
  int *piStack_6c;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined4 local_38;
  undefined4 uStack_34;
  int iStack_2c;
  
  iVar21 = *(int *)(DAT_00115f10 + 0x115bbe);
  iVar8 = 0;
  iStack_2c = **(int **)(DAT_0011662c + 0x115bc0);
  if (iVar21 != 0) {
    iVar8 = __xlogger_IsEnabledFor_impl();
  }
  local_548[0] = iVar8 != 0;
  local_488 = 0;
  uStack_480 = 0;
  local_478 = 0;
  local_540 = 0;
  uStack_538 = 0;
  local_530 = 0;
  auStack_52c._0_4_ = 0;
  auStack_52c._4_8_ = 0;
  local_520 = 0;
  local_518 = 0;
  local_510 = 0;
  local_50c = 0;
  if ((bool)local_548[0]) {
    local_540 = (ulonglong)(DAT_00115f18 + 0x115c1c) << 0x20;
    iVar8 = DAT_00115f1c + 0x115c28;
    uStack_538 = CONCAT44(iVar8,DAT_00115f14 + 0x115c18);
    local_530 = 0x182;
    auStack_52c._0_4_ = 0;
    gettimeofday((timeval *)auStack_52c,(__timezone_ptr_t)0x0);
    local_520 = 0xffffffffffffffff;
    local_518 = 0xffffffffffffffff;
    local_510 = 0xffffffff;
    local_50c = 0xffffffff;
    __strncpy_chk2(auStack_508,iVar8,0x80,0x80,10);
    local_488 = CONCAT44(auStack_52c._4_4_,auStack_52c._0_4_);
    local_489 = 0;
    FUN_00054da4(&local_470,0x400);
    FUN_00112538(&local_470);
    if (*(int *)(DAT_00115f24 + 0x115c7c) != 0) {
      __xlogger_Write_impl(&local_540,&local_470);
    }
  }
  piVar9 = (int *)FUN_0010c254();
  if (*piVar9 != *(int *)(DAT_00115f28 + 0x115c92)) {
    __s1_00 = (char *)(DAT_00115f2c + 0x115cd7);
    __s1 = __s1_00;
    if ((int *)piVar9[2] != (int *)0x0) {
      __s1 = (char *)(**(code **)(*(int *)piVar9[2] + 8))();
    }
    if ((__s1 == (char *)(DAT_00115f30 + 0x115ceb)) ||
       (iVar8 = strcmp(__s1,(char *)(DAT_00115f30 + 0x115ceb)), iVar8 == 0)) {
      FUN_00112588(&piStack_70);
      piVar9 = piStack_70;
      if (piStack_70 != (int *)0x0) {
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piStack_70);
          bVar4 = (bool)hasExclusiveAccess(piStack_70);
        } while (!bVar4);
        *piStack_70 = *piStack_70 + 1;
        DataMemoryBarrier(0x1b);
      }
      puVar12 = operator_new(0x2c);
      pvVar10 = operator_new(4);
      puVar12[10] = pvVar10;
      *puVar12 = pvVar10;
      puVar12[1] = 0;
      *(undefined1 *)(puVar12 + 9) = 0;
      puVar12[5] = 0;
      piVar11 = operator_new(0x10);
      iVar8 = DAT_00115f3c;
      *piVar11 = DAT_00115f38 + 0x115d2e;
      piVar11[3] = (int)puVar12;
      piVar1 = piVar11 + 2;
      *piVar1 = 1;
      piVar2 = piVar11 + 1;
      *piVar2 = 1;
      puVar17 = (undefined8 *)(DAT_00115f40 + 0x115d4e);
      if (piVar9 == (int *)0x0) {
        local_584 = (int *)0x0;
        local_58c = (ulonglong)CONCAT14(param_1 != 0,iVar8 + 0x115d4a);
        auStack_591._1_4_ = puVar17;
        local_470 = puVar17;
        if ((DAT_00115f40 & 1) == 0) goto LAB_00115efe;
LAB_001161c4:
        local_464 = local_584;
        local_46c = local_58c;
LAB_001161d0:
        auStack_591._1_4_ = (undefined8 *)0x0;
      }
      else {
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        auStack_591._1_4_ = 0;
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveAccess(piVar9);
          bVar4 = (bool)hasExclusiveAccess(piVar9);
        } while (!bVar4);
        *piVar9 = *piVar9 + 1;
        DataMemoryBarrier(0x1b);
        DataMemoryBarrier(0x1b);
        do {
          ExclusiveA
// ... [truncated]

```

