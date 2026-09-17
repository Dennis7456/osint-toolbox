# Transcript topic map

## Scope of the source

`transcript.txt` contains 53,153 words on a single line. It is the first half of
Heath Adams' OSINT Fundamentals course. The transcript explicitly says that the
unseen second half covers website, business, and wireless OSINT; a Linux lab;
automation and scripting; OSINT frameworks; report writing; and a challenge.
Those later subjects are therefore **promised by the speaker but not contained
in this file**.

The word ranges below are approximate navigation markers. They were calculated
from the raw transcript because it has no timestamps or paragraph boundaries.

## Topic divisions

| Approx. words | Topic | Enduring method | Transcript examples | Package treatment |
|---:|---|---|---|---|
| 1–1,275 | Course framing, ethics, and curriculum | Use public information for a legitimate, authorized purpose; methods outlast websites. | TCM course overview and explicit ethical warning. | Authority and purpose are mandatory when creating a case. |
| 1,276–1,829 | OSINT and the intelligence lifecycle | Planning/direction → collection → processing → analysis/production → dissemination, with iteration. | Client question and collection-to-report loop. | Target workflows, source/claim separation, and report output. |
| 1,830–3,815 | Note taking and screenshots | Keep organized notes; capture visual context; protect sensitive information. | KeepNote, CherryTree, OneNote, Notion, Joplin, Greenshot, Flameshot. | Joplin/Obsidian remain optional notes; Hunchly/ArchiveBox plus the case ledger are preferred for evidence. |
| 3,816–7,219 | Operational identities / “sock puppets” | Separate investigator activity from personal accounts and devices; understand attribution risk. | Fake Name Generator, AI-generated faces, separate email/social accounts, burner devices, virtual cards, VPNs, phone verification. | Reframed as research-account governance. Fake-persona generation, impersonation, deceptive engagement, and evasion are excluded by default. |
| 7,220–11,572 | Search-engine OSINT | Compare indexes; use exact phrases, Boolean operators, `site:`, `filetype:`, exclusions, wildcards, `intitle:`, `inurl:`, `intext:`, date/region filters, and advanced search. | Google, DuckDuckGo, Bing, Yandex, Baidu; Reddit and Tesla examples. | Reusable query recipes generate URLs without automatically sending requests. SearXNG is the optional self-hosted layer. |
| 11,573–12,980 | Reverse-image search | Search the same image across multiple visual indexes; compare exact and visually similar matches; pivot to source context. | Google Images, Yandex Images, TinEye. | Google Lens, Bing Visual Search, TinEye, and policy-gated Yandex; every upload requires a sensitivity check. |
| 12,981–14,163 | EXIF and file metadata | Preserve the original; inspect device, date, GPS, and other metadata; understand that platforms may strip fields. | Jeffrey's Image Metadata Viewer; iPhone/GPS example. | Local ExifTool is the default so sensitive originals need not be uploaded. Hash before analysis. |
| 14,164–16,091 | Physical-location reconnaissance | Use satellite and street imagery to understand a site's surroundings, access, visible controls, and context. | Google Maps satellite/street view; drone and site-visit discussion. | Remote public imagery is allowed within scope. Drone flights, trespass, surveillance, and on-site reconnaissance require separate authorization and are not automated. |
| 16,092–18,243 | Image geolocation | Decompose scenes into discriminating clues: vehicles, plates, language, signs, road markings, driving side, architecture, bridges, weather, terrain, and sun direction. | GeoGuessr and a detailed geolocation guide. | A media/location workflow combines OCR, maps, streetside/satellite imagery, SunCalc, and explicit matched/mismatched clues. |
| 18,244–20,745 | Geolocation exercises | Move from reverse search to clue extraction, candidate generation, map comparison, and corroboration. | Boston Copley Square/Fairmont Copley and Philadelphia PSFS examples. | Candidate locations remain hypotheses until multiple independent features match. |
| 20,746–23,717 | Email discovery and verification | Discover public organizational patterns, infer candidates cautiously, verify without unwanted contact, and correlate with public roles. | Hunter, Phonebook.cz, Voila Norbert, Clearbit Connect, Email Hippo, Email Checker, account-recovery examples. | Current licensed provider adapters are optional. Notification-triggering account recovery is prohibited by default. |
| 23,718–28,702 | Breach exposure / password OSINT | Breach data can reveal exposure, identifiers, and reused attributes; connect evidence carefully and keep a reproducible trail. | BreachParse, DeHashed, WeLeakInfo-like services, LeakCheck, Snusbase, Have I Been Pwned, Scylla, hashes.org, Hatemail; credential stuffing/spraying discussion. | Limited to HIBP or approved enterprise exposure metadata for self-owned/authorized addresses and verified domains. Password retrieval, hash cracking, stuffing, and spraying are excluded. |
| 28,703–30,490 | Username and account discovery | Enumerate a handle across platforms, manually verify candidates, save stable IDs, examine avatars/links/history, and avoid assuming identity from a shared username. | Namechk-like sites, account URL patterns, mobile-app search, reverse-image pivots. | WhatsMyName, Sherlock, and optional Maigret with rate limits and mandatory manual confirmation. |
| 30,491–32,452 | General people search | Combine exact names with context; use reverse phone/address and related-person leads; expect data-broker errors and removals. | Whitepages, TruePeopleSearch, FastPeopleSearch, FastBackgroundCheck, Webmii, PeekYou, 411, Spokeo, That'sThem, Google cache. | High-risk and jurisdiction-specific. Prefer official records, minimize PII, and use aggregators only as unverified leads. |
| 32,453–33,116 | Voter records | Search official/public electoral records only where lawful and relevant; note address and registration-date sensitivity. | voterrecords.com and state/county records. | Not a universal module. Implement as jurisdiction profiles with legal review and strong minimization. |
| 33,117–35,422 | Phone-number research | Try normalized formats, words, symbols, search engines, public directories, carrier/caller-ID leads, and international directories. | Google, Whitepages, Truecaller, CallerID Test, Yahoo recovery, Infobel. | Manual, jurisdiction-specific workflow. No contact-upload services with personal address books and no notification-triggering recovery. |
| 35,423–36,087 | Birth-date research | Look for public biographical records and dated congratulations; calculate carefully from post date and claimed age. | Google operators; Twitter/Facebook/LinkedIn birthday references. | Sensitive personal-data rule applies; corroborate and collect only when necessary. |
| 36,088–37,061 | Resumes and CVs | Search file types, images, document hosts, and professional profiles; extract work, education, dates, contacts, and metadata cautiously. | Google `filetype:`, Google Drive/Docs, Dropbox, Scribd, LinkedIn. | Document discovery recipes, local OCR/metadata, and source/artifact logging. |
| 37,062–40,052 | Twitter/X native search | Search keywords/hashtags, exact phrases, `from:`, `to:`, mentions, date windows, geocodes, media, and advanced search. | Native Twitter interface and profile timelines. | Prefer current native search or official API; geolocation signals are treated as weak/time-bound unless corroborated. |
| 40,053–43,248 | Twitter analytics/history tools | Examine posting patterns, sources/apps, interactions, stable numeric IDs, profile changes, and relationships. | SocialBearing, Twitonomy, Sleeping Time, Mentionmapp, TweetBeaver, Spoonbill, Tinfoleak. | Course-era services are treated as replaceable. Rebuild the method using approved APIs, archives, and graph exports. |
| 43,249–44,272 | TweetDeck monitoring | Use columns to monitor users, lists, keywords, searches, and permitted location queries in real time. | TweetDeck. | Now a conditional X Pro workflow; not a package dependency. |
| 44,273–47,249 | Facebook | Search people with contextual filters; inspect public posts/photos/tags, stable numeric IDs, relationships, check-ins, and page source; use friends' public content cautiously. | Native Facebook search; SOWsearch-like/Intelligence X search helper. | Public first-party views and approved APIs only. No deceptive connection requests, private-group access, or brittle scrapers. |
| 47,250–48,904 | Instagram | Review public profiles, posts, tags, following/followers, stable IDs, full-size public images, reverse-image leads, and search-engine results. | Native Instagram plus several third-party viewers/downloaders. | Third-party downloaders are excluded as fragile/ToS-sensitive. Use first-party public views/APIs and evidence capture. |
| 48,905–49,561 | Snapchat | Username correlation and public location-based posts. | Snap Map and slow-typing username suggestions. | Public Map content may be reviewed with real-time location safeguards; no precise tracking of vulnerable people. |
| 49,562–50,658 | Reddit | Search users, exact terms, posts, and comments; use `site:reddit.com`; combine small self-disclosures cautiously. | Reddit native and Google search. | Native/public search with strong identity-corroboration and minimization rules. |
| 50,659–52,299 | LinkedIn | Examine public profile/contact data, activity, employers, roles, education, projects, publications, recommendations, interests, and connections. | LinkedIn and LinkedIn Open Networker discussion. | Public search and licensed products only. No deceptive networking or bulk scraping. |
| 52,300–53,153 | TikTok and close | Review public videos, following, avatars, usernames, reverse-image leads, and historical search results. | TikTok/Musical.ly. | Native public search/API and evidence capture; old platform behavior is not assumed to persist. |

## Recurring methods extracted from the transcript

The strongest reusable ideas are not the named websites:

1. Start with an explicit question and authority.
2. Collect broadly enough to find leads, but only within scope.
3. Preserve the exact query, source URL, access time, and artifact.
4. Pivot across identifiers: name, username, email, phone, image, place,
   organization, domain, and time.
5. Compare more than one search index or provider.
6. Treat every match as a candidate until corroborated.
7. Build links and timelines while collecting, not only at the end.
8. Keep observations separate from inferences and conclusions.
9. Make the path to each conclusion reproducible.
10. Expect websites, APIs, interfaces, and access rules to change.

## Important gaps in the transcript

For a complete modern toolbox, the package adds subjects that this transcript
does not actually teach: evidence standards and provenance, web archiving,
domain/RDAP/DNS/certificate transparency, corporate registries, document OCR,
chronolocation, misinformation verification, entity resolution, graph exports,
data retention and deletion, team access controls, quality assurance, provider
health checks, and repeatable reporting.

