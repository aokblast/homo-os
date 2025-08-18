import { playMemeSound } from "../lib/sounds";

export default function HeroSection() {
  const handleReservationClick = () => {
    playMemeSound('beast');
    window.location.href = "https://tabelog.com/tokyo/A1318/A131802/13208234/"
  };

  const handleMenuClick = () => {
    const element = document.getElementById('menu');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section id="home" className="relative h-screen flex items-center justify-center overflow-hidden">
      {/* Background image */}
      <div 
        className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-70" 
        style={{backgroundImage: "url('https://mod.3dmgame.com/static/upload/logo/croppedImg_630f7d4941444.webp')"}}
      ></div>
      <div className="absolute inset-0 bg-gradient-to-b from-black/60 to-black/40"></div>
      
      <div className="relative z-10 text-center max-w-4xl mx-auto px-4">
        <h1 className="text-5xl md:text-7xl font-black text-white mb-6 meme-text-shadow animate-slide-in">
          いいよ！こいよ！<br />
          <span className="text-meme-orange">野獣レストラン</span>
        </h1>
        <p className="text-xl md:text-2xl text-meme-yellow mb-8 font-semibold animate-slide-in">
          先輩の聖地で最高の料理体験を！ Beast Day Special Available!
        </p>
        <div className="space-y-4 md:space-y-0 md:space-x-4 md:flex md:justify-center animate-slide-in">
          <button 
            onClick={handleReservationClick}
            className="bg-meme-orange hover:bg-dramatic-red text-white font-bold py-4 px-8 rounded-lg beast-glow transition-all duration-300 transform hover:scale-105 w-full md:w-auto"
            data-testid="button-reservation-hero"
          >
            今すぐ予約！ (114514円〜)
          </button>
          <button 
            onClick={handleMenuClick}
            className="bg-transparent border-2 border-meme-yellow text-meme-yellow hover:bg-meme-yellow hover:text-black font-bold py-4 px-8 rounded-lg transition-all duration-300 w-full md:w-auto"
            data-testid="button-menu-hero"
          >
            メニューを見る
          </button>
        </div>
      </div>
    </section>
  );
}