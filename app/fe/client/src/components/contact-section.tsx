import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Textarea } from "../components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "../components/ui/form";
import { useToast } from "../hooks/use-toast";
import { playMemeSound } from "../lib/sounds";

const contactSchema = z.object({
  name: z.string().min(1, "お名前を入力してください"),
  email: z.string().email("正しいメールアドレスを入力してください"),
  subject: z.string().min(1, "件名を選択してください"),
  message: z.string().min(1, "メッセージを入力してください"),
});

type ContactForm = z.infer<typeof contactSchema>;

export default function ContactSection() {
  const { toast } = useToast();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<ContactForm>({
    resolver: zodResolver(contactSchema),
    defaultValues: {
      name: "",
      email: "",
      subject: "",
      message: "",
    },
  });

  const onSubmit = async (data: ContactForm) => {
    setIsSubmitting(true);
    playMemeSound('iikoi');
    
    // Simulate form submission
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    toast({
      title: "送信完了！",
      description: "お問い合わせありがとうございます。24時間以内にお返事いたします。",
    });
    
    form.reset();
    setIsSubmitting(false);
  };

  return (
    <section id="contact" className="py-16 bg-gray-900">
      <div className="container mx-auto px-4">
        <h2 className="text-5xl font-black text-center text-meme-orange mb-12 meme-text-shadow">
          お問い合わせ
        </h2>
        
        <div className="grid md:grid-cols-2 gap-12 max-w-6xl mx-auto">
          <div className="space-y-8">
            <div className="bg-gray-800 rounded-xl p-6">
              <h3 className="text-2xl font-bold text-meme-yellow mb-4">店舗情報</h3>
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <i className="fas fa-map-marker-alt text-meme-orange text-xl mt-1"></i>
                  <div>
                    <p className="font-semibold text-white">住所</p>
                    <p className="text-gray-300">〒114-514 東京都下北沢1-14-5-14<br/>Kitazawa Sandingmu Park</p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <i className="fas fa-phone text-meme-orange text-xl mt-1"></i>
                  <div>
                    <p className="font-semibold text-white">電話番号</p>
                    <p className="text-gray-300">114-514-1919</p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <i className="fas fa-clock text-meme-orange text-xl mt-1"></i>
                  <div>
                    <p className="font-semibold text-white">営業時間</p>
                    <p className="text-gray-300">
                      ランチ: 11:45-14:51<br/>
                      ディナー: 17:00-23:30<br/>
                      定休日: 不定休
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <i className="fas fa-train text-meme-orange text-xl mt-1"></i>
                  <div>
                    <p className="font-semibold text-white">アクセス</p>
                    <p className="text-gray-300">下北沢駅から徒歩8分<br/>MAD気分で来店ください</p>
                  </div>
                </div>

		<div className="flex items-start space-x-3">
                  <i className="fas fa-link text-meme-orange text-xl mt-1"></i>
                  <div>
                    <p className="font-semibold text-white">関連リンク</p>
                    <p className="text-gray-300"><a className="flex rounded-lg bg-white/20 transition-colors" href="https://www.facebook.com/reel/483489504786387">ジオンの帰郷者</a><br/>
		      <a className="flex rounded-lg bg-white/20 transition-colors" href="https://www.facebook.com/p/%E5%B0%8F%E7%8C%AA%E5%8D%9A%E6%9E%97-100068360433799">こぶたボリン</a></p>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="bg-gradient-to-r from-beast-green to-digital-cyan rounded-xl p-6 text-white">
              <h3 className="text-xl font-bold mb-4">🎵 SNS Follow</h3>
              <div className="grid grid-cols-2 gap-4">
                <a href="#" className="flex items-center space-x-2 bg-white/20 rounded-lg p-3 hover:bg-white/30 transition-colors" data-testid="link-twitter">
                  <i className="fab fa-twitter text-xl"></i>
                  <span>@yaju_restaurant</span>
                </a>
                <a href="#" className="flex items-center space-x-2 bg-white/20 rounded-lg p-3 hover:bg-white/30 transition-colors" data-testid="link-instagram">
                  <i className="fab fa-instagram text-xl"></i>
                  <span>@beast_dining</span>
                </a>
                <a href="#" className="flex items-center space-x-2 bg-white/20 rounded-lg p-3 hover:bg-white/30 transition-colors" data-testid="link-youtube">
                  <i className="fab fa-youtube text-xl"></i>
                  <span>野獣レストラン</span>
                </a>
                <a href="#" className="flex items-center space-x-2 bg-white/20 rounded-lg p-3 hover:bg-white/30 transition-colors" data-testid="link-niconico">
                  <i className="fas fa-video text-xl"></i>
                  <span>ニコニコ動画</span>
                </a>
              </div>
            </div>
          </div>
          
          <div className="bg-gray-800 rounded-xl p-6">
            <h3 className="text-2xl font-bold text-meme-yellow mb-6">お問い合わせフォーム</h3>
            
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-white font-semibold">お名前 *</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="田所浩二" 
                          className="bg-gray-700 text-white border-gray-600" 
                          data-testid="input-contact-name"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-white font-semibold">メールアドレス *</FormLabel>
                      <FormControl>
                        <Input 
                          type="email" 
                          placeholder="yaju@example.com" 
                          className="bg-gray-700 text-white border-gray-600" 
                          data-testid="input-contact-email"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="subject"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-white font-semibold">件名</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger className="bg-gray-700 text-white border-gray-600" data-testid="select-contact-subject">
                            <SelectValue placeholder="件名を選択" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="reservation">予約について</SelectItem>
                          <SelectItem value="menu">メニューについて</SelectItem>
                          <SelectItem value="beast-day">野獣の日イベント</SelectItem>
                          <SelectItem value="collaboration">MAD動画コラボ</SelectItem>
                          <SelectItem value="other">その他</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="message"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-white font-semibold">メッセージ *</FormLabel>
                      <FormControl>
                        <Textarea 
                          placeholder="いいよ！こいよ！のような熱いメッセージをお待ちしています..." 
                          className="bg-gray-700 text-white border-gray-600 h-32" 
                          data-testid="textarea-contact-message"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <Button 
                  type="submit" 
                  disabled={isSubmitting}
                  className="w-full bg-meme-orange hover:bg-dramatic-red text-white font-bold py-4 rounded-lg beast-glow transition-all duration-300 transform hover:scale-105"
                  data-testid="button-submit-contact"
                >
                  {isSubmitting ? "送信中..." : "送信する！"}
                </Button>
              </form>
            </Form>
          </div>
        </div>
      </div>
    </section>
  );
}
