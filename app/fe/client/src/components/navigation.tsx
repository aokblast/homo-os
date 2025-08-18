import { useState } from "react";
import { useLocation } from "wouter";

export default function Navigation() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [location] = useLocation();

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
    setIsMobileMenuOpen(false);
  };

  return (
    <>
      <nav className="bg-gradient-to-r from-meme-orange to-dramatic-red shadow-lg sticky top-0 z-50">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-2">
              <i className="fas fa-utensils text-2xl text-meme-yellow"></i>
              <h1 className="text-xl font-black text-white meme-text-shadow">野獣レストラン 114514</h1>
            </div>
            <div className="hidden md:flex space-x-6">
              <button 
                onClick={() => scrollToSection('home')} 
                className="hover:text-meme-yellow transition-colors font-semibold"
                data-testid="nav-home"
              >
                ホーム
              </button>
              <button 
                onClick={() => scrollToSection('menu')} 
                className="hover:text-meme-yellow transition-colors font-semibold"
                data-testid="nav-menu"
              >
                メニュー
              </button>
              <button 
                onClick={() => scrollToSection('reservation')} 
                className="hover:text-meme-yellow transition-colors font-semibold"
                data-testid="nav-reservation"
              >
                予約
              </button>
              <button 
                onClick={() => scrollToSection('gallery')} 
                className="hover:text-meme-yellow transition-colors font-semibold"
                data-testid="nav-gallery"
              >
                ギャラリー
              </button>
              <button 
                onClick={() => scrollToSection('contact')} 
                className="hover:text-meme-yellow transition-colors font-semibold"
                data-testid="nav-contact"
              >
                連絡先
              </button>
            </div>
            <button 
              className="md:hidden text-white" 
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              data-testid="mobile-menu-toggle"
            >
              <i className="fas fa-bars text-xl"></i>
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <div className="md:hidden bg-dramatic-red">
          <div className="px-4 py-2 space-y-2">
            <button 
              onClick={() => scrollToSection('home')} 
              className="block py-2 text-white hover:text-meme-yellow w-full text-left"
              data-testid="mobile-nav-home"
            >
              ホーム
            </button>
            <button 
              onClick={() => scrollToSection('menu')} 
              className="block py-2 text-white hover:text-meme-yellow w-full text-left"
              data-testid="mobile-nav-menu"
            >
              メニュー
            </button>
            <button 
              onClick={() => scrollToSection('reservation')} 
              className="block py-2 text-white hover:text-meme-yellow w-full text-left"
              data-testid="mobile-nav-reservation"
            >
              予約
            </button>
            <button 
              onClick={() => scrollToSection('gallery')} 
              className="block py-2 text-white hover:text-meme-yellow w-full text-left"
              data-testid="mobile-nav-gallery"
            >
              ギャラリー
            </button>
            <button 
              onClick={() => scrollToSection('contact')} 
              className="block py-2 text-white hover:text-meme-yellow w-full text-left"
              data-testid="mobile-nav-contact"
            >
              連絡先
            </button>
          </div>
        </div>
      )}
    </>
  );
}