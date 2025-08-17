// Menu items with meme-themed names and prices
export const menuItems = [
  {
    name: "野獣寿司セット",
    description: "「いいよ！」と叫びたくなる絶品寿司。先輩厳選のネタを使用。",
    price: 11451,
    tag: "#114514 Special",
    image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT1j1PpyJGyIo08MVR3HEvJFyYgyI2oqYHngg&s"
  },
  {
    name: "先輩ラーメン",
    description: "「こいよ！」の一言で完成する究極のスープ。秘伝のタレ使用。",
    price: 1145,
    tag: "Beast Special",
    image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRH7u81NEpRUQ18ysr4C8xI_yONhOjN5smQuQ&s"
  },
  {
    name: "野獣和牛ステーキ",
    description: "MAD動画のように熱い和牛ステーキ。ニコニコ笑顔になれる一品。",
    price: 8100,
    tag: "Beast Day Special",
    image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRq073E_-0wC1PCCf_phouYxOodxVHOS2HgtO4Yja1uMqzEtTb0Xv7AQq-tftt5THtOI2g&usqp=CAU"
  },
  {
    name: "pudding",
    description: "MAD動画のように熱い和牛ステーキ。ニコニコ笑顔になれる一品。",
    price: 8100,
    tag: "Beast Day Special",
    image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTskxNrQsJau8suoydKjim25-BlucJP5R5fEQ&s"
  }
];

// Gallery items mixing restaurant photos with meme references
export const galleryItems = [
  {
    type: "image" as const,
    src: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/House_of_Beast_2020-11-05.jpg/1200px-House_of_Beast_2020-11-05.jpg",
    alt: "Dining room",
    label: "メインダイニング"
  },
  {
    type: "image" as const,
    src: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTZnDqpi1liS0hxa7D225kKm7I-LVewrJnvLw&s",
    alt: "Bar area",
    label: "野獣バー"
  },
  {
    type: "image" as const,
    src: "https://mod.3dmgame.com/static/upload/logo/croppedImg_630f7d4941444.webp",
    alt: "Private room",
    label: "114514個室"
  },
  {
    type: "image" as const,
    src: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTglgMsxipY5rZV8xXyO3nexRvgZydsE3pU8w&s",
    alt: "Private room",
    label: "114514個室"
  },
  
];

// Meme catchphrases and references
export const memePhrases = [
  "いいよ！こいよ！",
  "野獣先輩",
  "田所浩二",
  "114514",
  "ニコニコ動画",
  "MAD動画",
  "昏睡レイプ",
  "ｱｧｰ!",
  "野獣の日",
  "8月10日"
];

// Table names with meme references
export const tableNames = [
  { value: "beast", label: "野獣テーブル" },
  { value: "senpai", label: "先輩席" },
  { value: "114514", label: "114514ボックス" },
  { value: "mad", label: "MAD個室" },
  { value: "niconico", label: "ニコニコルーム" },
];

// Special dates and events
export const specialEvents = {
  beastDay: {
    date: "8月10日",
    name: "野獣の日",
    description: "年に一度の特別な日",
    discount: "全メニュー114514円引き",
    code: "BEAST810"
  }
};