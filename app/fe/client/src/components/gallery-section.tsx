import { galleryItems } from "@/lib/meme-data";

export default function GallerySection() {
  return (
    <section id="gallery" className="py-16 bg-gradient-to-b from-gray-800 to-gray-900">
      <div className="container mx-auto px-4">
        <h2 className="text-5xl font-black text-center text-meme-orange mb-12 meme-text-shadow">
          野獣ギャラリー
        </h2>
        
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {galleryItems.map((item: any, index: number) => (
            <div 
              key={index}
              className="relative group cursor-pointer"
              data-testid={`gallery-item-${index}`}
            >
              {item.type === 'image' ? (
                <img 
                  src={item.src} 
                  alt={item.alt} 
                  className="w-full h-48 object-cover rounded-lg shadow-lg group-hover:scale-105 transition-transform duration-300"
                />
              ) : (
                <div className={`${item.src} rounded-lg h-48 flex items-center justify-center`}>
                  <div className="text-center text-white">
                    <i className={`${item.icon} text-4xl mb-2`}></i>
                    <p className="font-bold">{item.title}</p>
                    <p className="text-sm">{item.subtitle}</p>
                  </div>
                </div>
              )}
              <div className="absolute inset-0 bg-black bg-opacity-50 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-center justify-center">
                <span className="text-white font-bold">{item.label}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}