// =============================================================================
// SHERLOCK SITES — the vendored Sherlock platform database, mapped into the
// T3MP3ST OsintSite catalog shape.
//
// Source: https://github.com/sherlock-project/sherlock (MIT, © 2019 Sherlock Project)
// Vendored verbatim at tools/sherlock/data.json (482 platforms).
//
// WHAT WE TAKE FROM SHERLOCK — not just the site list, but the three
// absence-detection techniques that make a username sweep honest:
//
//   1. errorType: status_code  → plain 2xx/404 check (the default).
//   2. errorType: message      → the page 200s even when the user does NOT exist;
//                                 the body carries one of a LIST of error markers.
//                                 2xx + any marker = ABSENT, 2xx clean = FOUND.
//                                 (Our curated catalog had a single-marker
//                                 `body_missing` for Steam; Sherlock has 127 such
//                                 sites, each with up to 6 markers.)
//   3. errorType: response_url → the site REDIRECTS a missing profile to a known
//                                 error page. 2xx is meaningless; the FINAL URL is
//                                 the signal. 27 sites.
//   4. regexCheck              → the platform only accepts usernames of a certain
//                                 shape. Probing an impossible username yields a
//                                 guaranteed-false ABSENT, so we SKIP it instead.
//                                 95 sites carry one.
//
// Also honored: urlProbe (52 sites ship a dedicated API/cleaner URL — probed
// instead of the human page), isNSFW (19 sites — catalogued but kept out of
// default sweeps), and request_method POST (3 sites — NOT supported here; they
// are dropped rather than mis-probed, see SKIPPED_POST).
//
// Merge policy: our curated entries WIN on name collision. They carry API
// endpoints and identity corroboration that a generic page check cannot, and
// a weaker duplicate would only add noise. Sherlock fills in everything else.
// =============================================================================

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { OsintSite, OsintSiteCategory } from './osint.js';

export const SHERLOCK_SOURCE = 'https://github.com/sherlock-project/sherlock';
export const SHERLOCK_LICENSE = 'MIT — © 2019 Sherlock Project';
export const SHERLOCK_DATA_URL =
  'https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json';

export const SHERLOCK_VENDOR_DIR = join(
  dirname(fileURLToPath(import.meta.url)), '..', '..', 'tools', 'sherlock'
);
export const SHERLOCK_DATA_PATH = join(SHERLOCK_VENDOR_DIR, 'data.json');

/** Raw shape of one entry in Sherlock's data.json. */
export interface SherlockEntry {
  __comment__?: string;
  errorType?: 'status_code' | 'message' | 'response_url';
  errorUrl?: string;
  errorCode?: number;
  url?: string;
  urlMain?: string;
  urlProbe?: string;
  regexCheck?: string;
  username_claimed?: string;
  isNSFW?: boolean;
  request_method?: 'GET' | 'POST' | 'HEAD' | 'PUT';
  request_payload?: unknown;
  headers?: Record<string, string>;
  /** The shipped database uses a bare string here far more often than a list. */
  errorMsg?: string | string[];
}

export type SherlockData = Record<string, SherlockEntry>;

/** POST-only sites: probing them with GET silently produces a false ABSENT, so
 *  they are dropped from the merge and reported instead. Adding real POST support
 *  would mean threading a request body through every probe tier (egress → Tor → direct). */
const SKIPPED_POST = new Set(['Anilist', 'Discord', 'Holopin']);

// ── category inference ───────────────────────────────────────────────────────
// Sherlock ships no categories. Infer from the platform name + host so the
// merged catalog still groups sensibly in the UI. Rules are ordered — first
// match wins — and deliberately free of bare-letter alternatives.
const CATEGORY_RULES: Array<[RegExp, OsintSiteCategory]> = [
  [/(?:^|[^a-z])(?:github|gitlab|bitbucket|codeberg|gitea|forgejo|sourcehut|gitcode|notabug|codeberg|launchpad|npmjs|npmjs|pypi|packagist|dockerhub|docker|replit|codepen|codesandbox|stackblitz|observablehq|sourceforge|codewars|codingame|leetcode|hackerrank|hackthebox|tryhackme|topcoder|codechef|projecteuler|buttup|kaggle|huggingface|replicate|modelscope|civitai|dev\.?to|hashnode|freecodecamp|codecademy|datacamp|coursera|udemy|skillshare|scratch|roblox|programiz|w3resource|sololearn|exercism|rustlings|adventofcode|dailycoding|maven|php|artisan|packagist|laravel|symfony|django|flask)(?:[^a-z]|$)/i, 'dev'],
  [/(?:^|[^a-z])(?:steam|roblox|playstation|xbox|nintendo|epicgames|battle\.?net|riotgames|ubisoft|origin|ea\.?com|leagueoflegends|dota|steamcommunity|clashofclans|clashroyale|clash royale|miniclip|newgrounds|moddb|itch\.?io|rawg|igdb|mobygames|gamefaqs|gamespot|gamekulti|gamesplanet|chess\.?com|lichess|chess24|chessable|duolingo|osu|trackmania|hypixel|roblox|garena|supercell|mobizen|hunterlab|armored warfare|crossfire|faceit|gamerig|tracker.gg|trackerNetwork|valorant|destiny|tarkov|escape from tarkov|pubg|fortnite|minecraft|terraria|runescape|stellaris|warframe|path of exile|twitch|just chatting|counter-strike|css|osu!|pokebattler|verdant|skribbl|geoGuessr)/i, 'gaming'],
  [/(?:^|[^a-z])(?:pornhub|xvideos|xhamster|redtube|youporn|chaturbate|bongacams|erome|motherless|lushstories|image ?fap|pocketstars|tnaflix|rocket ?tube|admireme|apclips|heavy-r|forum ophilia|all ?things ?worn|spankbang|thisav|hitomi|javhd|openload|fansly|onlyfans|boosty|cam4|myfreecams|stripchat)(?:[^a-z]|$)/i, 'adult'],
  [/(?:youtube|vimeo|dailymotion|peertube|odysee|bitchute|rumble|triller|nicovideo|niconico|weibo|afreeca|soop|veoh|vidyard|voo|iqiyi|youku|dailymotion|streamable|peertube|cloudcast|veoh|wetransfer|videvo|clipset|breakthru|motionelements|filmot|videohive|openload|vidzi|streamtape|mp4upload|doodstream|ok.ru|vkvideo|likee|smotrim|chaturbate|playeurl|bitmix|filenode|filemoon|drivevn|ok.ru|rutube|seznam|odnoklassniki)/i, 'video'],
  [/(?:spotify|soundcloud|bandcamp|musicmap|musicbrainz|last\.?fm|mixcloud|audiomack|deezer|beatport|discogs|anchor ?fm|7digital|chorus|gentlemen|playmusic|reverbnation|songkick|distrokid|audioboom|purefitness|musicjane|jiosaavn|everynoise|music ?brain|mp3|lyrics|musixmatch|bandhelper|genius|musicxmatch|napster|yandex ?music|musicmap|hearthis|mixcloud|myfitnesspal|musicbrainz)/i, 'music'],
  [/(?:artstation|behance|dribbble|flickr|500px|unsplash|pexels|pixiv|deviantart|displate|9gag|figma|virsu|redbubble|society6|deviantart|art ?vote|awwwards|coroflot|behance|muzmatch|artconnect|artstation|deviantart|slidshare|scribd|issuu|slideshare|rawpixel|unlimitedpng|wallpapercave|pinimg|pinterest|carrd|neocities|glitch\.?me|replit|observablehq|codePen|deviantart|artmajeur|behance|deviantart|artstation|dribbble|flickr|unsplash|pexels|artifex|exhange)/i, 'art'],
  [/(?:patreon|buymeacoffee|ko-?fi|flattr|liberapay|opencollective|hackerone|bugcrowd|tipjar|gofundme|donorschoose|ethereum|crypto|bitcoin|wallet|coinbase|binance|blockchain|cardano|polkadot|solana|monero|litecoin|dogecoin|onlyfans|fansly|boosty|paypal|venmo|cash ?app|wise|revolut|stripe|paddle|gumroad|itch\.?io|patreon|deviantart|artstation|boosty|donate|support|pledge|subscription|membership|supporter|funding|sell|shop|store|marketplace|buy)/i, 'money'],
  [/(?:medium|substack|wordpress|blogger|blogspot|ghost|beehiiv|buttondown|write\.?freely|notion|wikidot|weebly|wix|typepad|postsmith|pravatar|about\.me|disqus|letterboxd|goodreads|shelf|sameenergy| wattpad|fictionpress|penpal|wikiwand|scp ?wiki|penpal|blog|newsletter|magazine|writer|author|poetry|quotes|diary|journal)/i, 'blog'],
  [/(?:telegram|discord|signal|whatsapp|wechat|line|skype|teams|slack|zulip|element|mattermost|rocket\.?chat|keybase|matrix|threema|wire|viber|talk|revolt|guilded|hey|imessage|mailspring|openmail|rain ?drop|pocket|mailbox|podo|smooch|napcat|talkatone|joinme|appear|imo|voxer|ciallo|trillian|hexchat|mobycle|riot ?games|revolt\.?app|mewe|gettr|mastodon|pleroma|mastodon)/i, 'messaging'],
  [/(?:forum|community|discuss|discussion|board|ask|answer|quora|stack ?exchange|4chan|9gag|lemmy|discourse|tildes|proboards|secondlife|habbo|amino|hacker ?earth|hacker ?one|bitbucket|code ?review|producthunt|hacker ?news|slashdot|lobsters|metafilter|askfm|justapedia|notefile|resumebuilder|topic|thread|message ?board|q&a|support)/i, 'forum'],
  [/(?:facebook|instagram|twitter|tiktok|snapchat|pinterest|threads|bluesky|tumblr|reddit|linkedin|weibo|xiaohongshu|wykop|okrut|naver|parler|truthsocial|gab|bitchute|lemon8|beboo|coomer|dts?e|onlyfans|fansly|boosty|donmeg|slideshare|flickr|mixcloud|bandcamp|goodreads|letterboxd|myanimelist|anilist|trakt|chess|duolingo|quizlet|quora|deviantart|artstation|behance|dribbble|codepen|linkedin|profile|user|member|people|community|social|follow|friend|page|account)/i, 'social'],
];

/** Hosts whose "profile exists" signal is unreliable even when the page 200s. */
const SOFT_200_HOSTS = [
  'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'tiktok.com', 'pinterest.com',
  'snapchat.com', 'threads.net', 'tumblr.com', 'weibo.com', 'xiaohongshu.com', 'vk.com',
  'quora.com', 'flickr.com', '500px.com', '9gag.com', 'weibo.cn',
];

const ADULT_HOST_HINTS = /(porn|xvideos|xhamster|redtube|youporn|chaturbate|bongacams|erome|motherless|lushstories|imagefap|pocketstars|tnaflix|rocket ?tube|admireme|apclips|heavy-r|ophelia|allthingsworn|onlyfans|fansly|boosty|cam4|stripchat|spankbang|javhd)/i;

function hostOf(url: string): string {
  const m = url.match(/^https?:\/\/([^/:?#]+)/i);
  return (m?.[1] || '').toLowerCase();
}

export function inferSherlockCategory(name: string, entry: SherlockEntry): OsintSiteCategory {
  if (entry.isNSFW || ADULT_HOST_HINTS.test(name) || ADULT_HOST_HINTS.test(entry.url || '')) return 'adult';
  const hay = `${name} ${entry.url || ''} ${entry.urlMain || ''}`;
  for (const [re, cat] of CATEGORY_RULES) {
    if (re.test(hay)) return cat;
  }
  return 'social';
}

/** Read + cache the vendored database. Returns an empty map when the file is
 *  missing (e.g. a slim deploy) so the curated catalog still sweeps fine. */
let cached: SherlockData | null = null;
export function loadSherlockData(dataPath: string = SHERLOCK_DATA_PATH): SherlockData {
  if (cached && dataPath === SHERLOCK_DATA_PATH) return cached;
  if (!existsSync(dataPath)) return {};
  try {
    const parsed = JSON.parse(readFileSync(dataPath, 'utf8')) as SherlockData;
    delete (parsed as Record<string, unknown>).$schema;
    if (dataPath === SHERLOCK_DATA_PATH) cached = parsed;
    return parsed;
  } catch {
    return {};
  }
}

export interface SherlockMapResult {
  sites: OsintSite[];
  /** Names in the database we deliberately did not map (POST-only, or malformed). */
  skipped: string[];
  /** Raw entry counts by errorType, for the UI/status line. */
  byErrorType: Record<string, number>;
}

/** Sherlock templates use `{}`; ours use `{u}`. A handful of entries also ship a
 *  plaintext http:// probe (Gravatar among them) — upgraded to https because the
 *  probe carries a username in the URL and must not cross the network in clear.
 *  Sites that only answer on http redirect to https anyway, so nothing is lost. */
function normalizeTemplate(tpl: string): string {
  const withToken = tpl.replaceAll('{}', '{u}');
  return withToken.startsWith('http://') ? `https://${withToken.slice('http://'.length)}` : withToken;
}

/** Map one Sherlock entry → OsintSite, or null when it cannot be represented. */
export function mapSherlockEntry(name: string, entry: SherlockEntry): OsintSite | null {
  if (!entry || typeof entry !== 'object') return null;
  if (entry.request_method && entry.request_method !== 'GET') return null; // POST/HEAD need a request-body tier

  // Sherlock's `url` is the human profile page; a few entries only carry a
  // `urlProbe` with the placeholder (API-only checks). Prefer whichever has it.
  const humanRaw = entry.url && entry.url.includes('{}') ? entry.url : '';
  const probeRaw = entry.urlProbe && entry.urlProbe.includes('{}') ? entry.urlProbe : '';
  if (!humanRaw && !probeRaw) return null;

  const urlTemplate = normalizeTemplate(humanRaw || probeRaw);
  // A dedicated probe URL is strictly better than the human page (clean 404s).
  const probeUrlTemplate = probeRaw ? normalizeTemplate(probeRaw) : urlTemplate;
  const category = inferSherlockCategory(name, entry);
  const host = hostOf(probeUrlTemplate);
  const soft200 = SOFT_200_HOSTS.some((h) => host.endsWith(h));

  const base: OsintSite = {
    name,
    category,
    urlTemplate,
    probeUrlTemplate,
    probeType: 'status',
    // Sherlock's own data carries no reliability opinion. A dedicated API probe
    // gives a clean signal; a soft-200 login wall makes a FOUND nearly worthless.
    reliability: entry.urlProbe ? 'medium' : soft200 ? 'low' : 'medium',
    source: 'sherlock',
    adult: category === 'adult',
    notes: [
      probeRaw ? 'dedicated probe URL' : undefined,
      entry.regexCheck ? 'username-shape pre-filter' : undefined,
      entry.errorType && entry.errorType !== 'status_code' ? `absence via ${entry.errorType}` : undefined,
    ].filter(Boolean).join(' · ') || undefined,
  };

  if (entry.regexCheck) {
    try { new RegExp(entry.regexCheck); base.usernameRegex = entry.regexCheck; } catch { /* invalid regex — ignore, probe normally */ }
  }

  // `errorMsg` is a bare string in most of the database and an array in a few —
  // normalize both into the any-of marker list.
  const markers = (Array.isArray(entry.errorMsg) ? entry.errorMsg : entry.errorMsg ? [entry.errorMsg] : [])
    .filter((m): m is string => typeof m === 'string' && m.length > 0);

  if (entry.errorType === 'message' && markers.length) {
    base.absentMarkers = markers;
    base.probeType = 'body_contains'; // classifier reads absentMarkers, not probeValue
  } else if (entry.errorType === 'response_url' && entry.errorUrl) {
    base.absentRedirectPrefix = normalizeTemplate(entry.errorUrl);
  } else if (entry.errorType === 'status_code' || !entry.errorType) {
    base.probeType = 'status';
  } else if (entry.errorType === 'message') {
    // Declares message-type absence but ships no marker — the classifier would
    // have to guess, and a wrong ABSENT is worse than an honest UNKNOWN.
    return null;
  } else {
    return null;
  }
  return base;
}

export function mapSherlockData(data: SherlockData): SherlockMapResult {
  const sites: OsintSite[] = [];
  const skipped: string[] = [];
  const byErrorType: Record<string, number> = {};
  for (const [name, entry] of Object.entries(data)) {
    if (name === '$schema' || !entry || typeof entry !== 'object') continue;
    if (SKIPPED_POST.has(name) || (entry.request_method && entry.request_method !== 'GET')) {
      skipped.push(name);
      continue;
    }
    const et = entry.errorType || 'status_code';
    byErrorType[et] = (byErrorType[et] || 0) + 1;
    const site = mapSherlockEntry(name, entry);
    if (site) sites.push(site);
    else skipped.push(name);
  }
  return { sites, skipped, byErrorType };
}

/** The full merged catalog: curated entries win on name collision. */
export function buildSherlockMergedCatalog(
  curated: OsintSite[],
  data: SherlockData = loadSherlockData()
): { catalog: OsintSite[]; sherlockCount: number; curatedCount: number; skipped: string[]; byErrorType: Record<string, number> } {
  const mapped = mapSherlockData(data);
  const taken = new Set(curated.map((s) => s.name.trim().toLowerCase()));
  const fresh = mapped.sites.filter((s) => !taken.has(s.name.trim().toLowerCase()));
  for (const s of curated) if (!s.source) s.source = 'curated';
  return {
    catalog: [...curated, ...fresh],
    sherlockCount: fresh.length,
    curatedCount: curated.length,
    skipped: mapped.skipped,
    byErrorType: mapped.byErrorType,
  };
}
