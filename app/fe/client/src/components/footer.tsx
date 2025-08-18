export default function Footer() {
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="bg-black py-8">
      <div className="container mx-auto px-4">
        <div className="grid md:grid-cols-3 gap-8">
          <div>
            <h3 className="text-xl font-bold text-meme-orange mb-4">野獣レストラン 114514</h3>
            <p className="text-gray-400">先輩の聖地で最高の料理体験を。<br/>2001年から続く伝説の味をお楽しみください。</p>
          </div>
          
          <div>
            <h4 className="text-lg font-bold text-white mb-4">クイックリンク</h4>
            <ul className="space-y-2">
              <li>
                <button 
                  onClick={() => scrollToSection('menu')} 
                  className="text-gray-400 hover:text-meme-yellow transition-colors"
                  data-testid="footer-link-menu"
                >
                  メニュー
                </button>
              </li>
              <li>
                <button 
                  onClick={() => scrollToSection('reservation')} 
                  className="text-gray-400 hover:text-meme-yellow transition-colors"
                  data-testid="footer-link-reservation"
                >
                  予約
                </button>
              </li>
              <li>
                <button 
                  onClick={() => scrollToSection('gallery')} 
                  className="text-gray-400 hover:text-meme-yellow transition-colors"
                  data-testid="footer-link-gallery"
                >
                  ギャラリー
                </button>
              </li>
              <li>
                <button 
                  onClick={() => scrollToSection('contact')} 
                  className="text-gray-400 hover:text-meme-yellow transition-colors"
                  data-testid="footer-link-contact"
                >
                  お問い合わせ
                </button>
              </li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-lg font-bold text-white mb-4">野獣の日情報</h4>
            <div className="bg-gradient-to-r from-beast-day to-dramatic-red rounded-lg p-4">
              <p className="text-white font-bold">8月10日</p>
              <p className="text-meme-yellow">年に一度の特別な日</p>
              <p className="text-sm text-gray-200">全メニュー114514円引き</p>
            </div>
          </div>
        </div>
        
        <div className="border-t border-gray-800 mt-8 pt-8 text-center">
          <p className="text-gray-400">
            © 2024 野獣レストラン 114514. All rights reserved. 
            <span className="text-meme-orange"> いいよ！こいよ！</span>
          </p>
          <p className="text-gray-500 text-sm mt-2">
            This website is a parody/tribute site for entertainment purposes only.
          </p>
        </div>
      </div>
    </footer>
  );
}