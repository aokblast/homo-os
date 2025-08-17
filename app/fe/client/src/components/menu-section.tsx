import { menuItems } from "@/lib/meme-data";

export default function MenuSection() {
  return (
    <section id="menu" className="py-16 bg-gradient-to-b from-gray-900 to-gray-800">
      <div className="container mx-auto px-4">
        <h2 className="text-5xl font-black text-center text-meme-orange mb-12 meme-text-shadow">
          野獣メニュー Collection
        </h2>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {menuItems.map((item: any, index: number) => (
            <div 
              key={index}
              className="bg-gray-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105"
              data-testid={`menu-item-${index}`}
            >
              <img 
                src={item.image} 
                alt={item.name} 
                className="w-full h-48 object-cover rounded-lg mb-4"
              />
              <h3 className="text-xl font-bold text-meme-yellow mb-2">{item.name}</h3>
              <p className="text-gray-300 mb-4">{item.description}</p>
              <div className="flex justify-between items-center">
                <span className="text-2xl font-bold text-meme-orange">¥{item.price.toLocaleString()}</span>
                <span className="text-sm text-digital-cyan">{item.tag}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}