import Navigation from "@/components/navigation";
import HeroSection from "@/components/hero-section";
import MenuSection from "@/components/menu-section";
import ReservationSection from "@/components/reservation-section";
import GallerySection from "@/components/gallery-section";
import ContactSection from "@/components/contact-section";
import Footer from "@/components/footer";
import { useEffect } from "react";

export default function Home() {
  useEffect(() => {
    // Easter egg: 114514 sequence detector
    let sequence: string[] = [];
    const targetSequence = ['1', '1', '4', '5', '1', '4'];
    
    const handleKeydown = (e: KeyboardEvent) => {
      sequence.push(e.key);
      if (sequence.length > targetSequence.length) {
        sequence.shift();
      }
      
      if (sequence.join('') === targetSequence.join('')) {
        document.body.style.animation = 'beast-pulse 2s infinite';
        setTimeout(() => {
          document.body.style.animation = '';
        }, 6000);
      }
    };
    
    document.addEventListener('keydown', handleKeydown);
    return () => document.removeEventListener('keydown', handleKeydown);
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <Navigation />
      <HeroSection />
      
      {/* Beast Day Special Banner */}
      <section className="bg-gradient-to-r from-beast-day to-dramatic-red py-8">
        <div className="container mx-auto px-4 text-center">
          <div className="animate-meme-bounce inline-block">
            <i className="fas fa-fire text-4xl text-meme-yellow mb-2"></i>
          </div>
          <h2 className="text-3xl font-black text-white mb-2 meme-text-shadow">
            野獣の日スペシャル！ August 10th Only!
          </h2>
          <p className="text-xl text-meme-yellow font-semibold">
            全メニュー114514円引き！先輩に敬意を表して特別価格でご提供！
          </p>
        </div>
      </section>

      {/* About Section */}
      <section className="py-16 bg-gray-800">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-4xl font-black text-meme-orange mb-6 meme-text-shadow">
                野獣先輩の聖地へようこそ
              </h2>
              <p className="text-lg text-gray-300 mb-6 leading-relaxed">
                2001年の伝説から始まった野獣先輩の文化を料理で表現。ニコニコ動画で生まれたMAD文化と、
                本格的な日本料理を融合させた唯一無二のレストランです。
              </p>
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-meme-orange/20 p-4 rounded-lg">
                  <i className="fas fa-calendar-alt text-meme-orange text-2xl mb-2"></i>
                  <h3 className="font-bold text-white">営業時間</h3>
                  <p className="text-gray-300">11:45-14:51</p>
                  <p className="text-gray-300">17:00-23:30</p>
                </div>
                <div className="bg-digital-cyan/20 p-4 rounded-lg">
                  <i className="fas fa-users text-digital-cyan text-2xl mb-2"></i>
                  <h3 className="font-bold text-white">収容人数</h3>
                  <p className="text-gray-300">最大114名様</p>
                  <p className="text-gray-300">個室あり</p>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <img 
                src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/House_of_Beast_2020-11-05.jpg/1200px-House_of_Beast_2020-11-05.jpg" 
                alt="Traditional dining" 
                className="rounded-lg shadow-lg w-full h-48 object-cover"
              />
              <img 
                src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTZnDqpi1liS0hxa7D225kKm7I-LVewrJnvLw&s" 
                alt="Traditional dining" 
                className="rounded-lg shadow-lg w-full h-48 object-cover"
              />
              <img 
                src="https://mod.3dmgame.com/static/upload/logo/croppedImg_630f7d4941444.webp" 
                alt="Traditional dining" 
                className="rounded-lg shadow-lg w-full h-48 object-cover"
              />
              <img 
                src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTglgMsxipY5rZV8xXyO3nexRvgZydsE3pU8w&s" 
                alt="Traditional dining" 
                className="rounded-lg shadow-lg w-full h-48 object-cover"
              />
            </div>
          </div>
        </div>
      </section>

      <MenuSection />
      <ReservationSection />
      <GallerySection />
      <ContactSection />
      <Footer />
    </div>
  );
}
