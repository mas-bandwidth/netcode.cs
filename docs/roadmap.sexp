; The netcode.cs roadmap: the data ROADMAP.md is generated from.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment):
; data, never evaluated. Edit this file, then regenerate ROADMAP.md with nova-sprint's
; generator, from a nova-sprint checkout:
;   go build -o /tmp/roadmap ./tools/roadmap && (cd <this repo> && /tmp/roadmap --file docs/roadmap.sexp --out ROADMAP.md)
; Never edit ROADMAP.md by hand. Created 2026-10-14 when the open sprint cards of this
; repository were moved out of the stopped sprint.
(roadmap "v1"
 :title "netcode.cs roadmap"
 :text "Planned work for netcode.cs. Each item below was an open sprint card, moved out of the stopped sprint on 2026-10-14; it names its card, its tier, its base branch and any pushed work to resume from. Landed work is in git."

 :groups
 (
  (group "export-netcode-cs-port" :title "Moved out of the sprint on 2026-10-14: netcode-cs-port"
   :text "The open cards of sprint stream netcode-cs-port, moved out of the stopped sprint on 2026-10-14, one item per card. Landed cards of the stream are in git and are not listed. Each item names its card, its tier, its base branch and any pushed work to resume from.")
 )

 :items
 (
  (item "cs-netcode-disconnect-callback-cannot-reenter-a-clearing-slot" :group "export-netcode-cs-port" :area "netcode.cs"
   :title "Cs netcode disconnect callback cannot reenter a clearing slot"
   :text "Server.DisconnectClientInternal calls the callback at src/Server.cs:563 and clears the slot at 580-584; a re-entrant disconnect reaches ClientIndex[-1] at :580 and throws IndexOutOfRangeException, and a callback with no self-guard recurses to an uncatchable StackOverflow."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-netcode-disconnect-callback-cannot-reenter-a-clearing-slot (stream netcode-cs-port, column working, tier pro, base sprint/netcode-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-netcode-disconnect-callback-cannot-reenter-a-clearing-slot" :sprint-stream "netcode-cs-port" :sprint-column "working" :tier "pro" :sprint-base "sprint/netcode-cs-port" :needs "cs-netcode-connection-response-takes-only-its-own-mappings-challenge" :pushed-head "" :pushed-branch ""))
  (item "cs-netcode-replay-top-sequence-and-restart-floor-edges" :group "export-netcode-cs-port" :area "netcode.cs"
   :title "Cs netcode replay top sequence and restart floor edges"
   :text "N4: `if (sequence == ulong.MaxValue) return true;` first in AlreadyReceived."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-netcode-replay-top-sequence-and-restart-floor-edges (stream netcode-cs-port, column waiting, tier pro, base sprint/netcode-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-netcode-replay-top-sequence-and-restart-floor-edges" :sprint-stream "netcode-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-cs-port" :needs "cs-netcode-disconnect-callback-cannot-reenter-a-clearing-slot,netfix-restart-floor-refuses-a-token-from-the-start-second" :pushed-head "" :pushed-branch ""))
  (item "cs-netcode-token-lifetimes-are-bounded" :group "export-netcode-cs-port" :area "netcode.cs"
   :title "Cs netcode token lifetimes are bounded"
   :text "N7: a pure PreconnectExpireTime( time, timeoutSeconds ) returning time + (timeoutSeconds > 0 ? timeoutSeconds : Defines.PreconnectMappingSeconds /* 10 */), used at src/Server.cs:714."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-netcode-token-lifetimes-are-bounded (stream netcode-cs-port, column waiting, tier pro, base sprint/netcode-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-netcode-token-lifetimes-are-bounded" :sprint-stream "netcode-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-cs-port" :needs "cs-netcode-replay-top-sequence-and-restart-floor-edges,netfix-preconnect-mapping-lifetime-ignores-a-nonpositive-token-timeout,netfix-never-expiring-tokens-are-refused-or-documented-against-the-restart-floor" :pushed-head "" :pushed-branch ""))
  (item "cs-netcode-client-refuses-a-server-address-it-has-no-socket-for" :group "export-netcode-cs-port" :area "netcode.cs"
   :title "Cs netcode client refuses a server address it has no socket for"
   :text "The port never touches a closed descriptor (`socketIpv4?.` at src/Netcode.cs:1990, 1994; null checks at src/Client.cs:508-517) but silently drops sends, and Connect and ConnectToNextServer (src/Client.cs:348-349, 630-631) never skip the address or set InvalidConnectToken."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-netcode-client-refuses-a-server-address-it-has-no-socket-for (stream netcode-cs-port, column waiting, tier pro, base sprint/netcode-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-netcode-client-refuses-a-server-address-it-has-no-socket-for" :sprint-stream "netcode-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-cs-port" :needs "cs-netcode-token-lifetimes-are-bounded,netfix-client-refuses-a-server-address-it-has-no-socket-for" :pushed-head "" :pushed-branch ""))
  (item "cs-netcode-global-packet-nonces-differ-between-servers-sharing-a-token" :group "export-netcode-cs-port" :area "netcode.cs"
   :title "Cs netcode global packet nonces differ between servers sharing a token"
   :text "Cs netcode global packet nonces differ between servers sharing a token. Done when: the new tests are red before the fix and green after it;"
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-netcode-global-packet-nonces-differ-between-servers-sharing-a-token (stream netcode-cs-port, column waiting, tier pro, base sprint/netcode-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-netcode-global-packet-nonces-differ-between-servers-sharing-a-token" :sprint-stream "netcode-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-cs-port" :needs "cs-netcode-client-refuses-a-server-address-it-has-no-socket-for,netfix-global-packet-nonces-differ-between-servers-sharing-a-token" :pushed-head "" :pushed-branch ""))
))
