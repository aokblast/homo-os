import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useToast } from "@/hooks/use-toast";
import { playMemeSound } from "@/lib/sounds";

const reservationSchema = z.object({
  name: z.string().min(1, "お名前を入力してください"),
  date: z.string().min(1, "予約日を選択してください"),
  time: z.string().min(1, "時間を選択してください"),
  guests: z.string().min(1, "人数を選択してください"),
  table: z.string().optional(),
  phone: z.string().min(1, "電話番号を入力してください"),
  requests: z.string().optional(),
});

type ReservationForm = z.infer<typeof reservationSchema>;

export default function ReservationSection() {
  const { toast } = useToast();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<ReservationForm>({
    resolver: zodResolver(reservationSchema),
    defaultValues: {
      name: "",
      date: "",
      time: "",
      guests: "",
      table: "",
      phone: "",
      requests: "",
    },
  });

  const onSubmit = async (data: ReservationForm) => {
    setIsSubmitting(true);
    playMemeSound('iikoi');
    
    // Simulate form submission
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    toast({
      title: "いいよ！予約完了！",
      description: "ご予約ありがとうございます。確認のメールをお送りいたします。",
    });
    
    form.reset();
    setIsSubmitting(false);
  };

  return (
    <section id="reservation" className="py-16 bg-gray-900">
      <div className="container mx-auto px-4">
        <h2 className="text-5xl font-black text-center text-meme-orange mb-12 meme-text-shadow">
          野獣予約システム
        </h2>
        
        <div className="max-w-4xl mx-auto">
          <div className="grid md:grid-cols-2 gap-8">
            {/* Reservation Form */}
            <div className="bg-gray-800 rounded-xl p-8 shadow-lg">
              <h3 className="text-2xl font-bold text-meme-yellow mb-6">予約フォーム</h3>
              
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
                            data-testid="input-name"
                            {...field} 
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="date"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-white font-semibold">予約日 *</FormLabel>
                          <FormControl>
                            <Input 
                              type="date" 
                              className="bg-gray-700 text-white border-gray-600" 
                              data-testid="input-date"
                              {...field} 
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="time"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-white font-semibold">時間 *</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger className="bg-gray-700 text-white border-gray-600" data-testid="select-time">
                                <SelectValue placeholder="時間を選択" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="11:45">11:45</SelectItem>
                              <SelectItem value="14:51">14:51</SelectItem>
                              <SelectItem value="17:00">17:00</SelectItem>
                              <SelectItem value="19:30">19:30</SelectItem>
                              <SelectItem value="21:45">21:45</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="guests"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-white font-semibold">人数 *</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger className="bg-gray-700 text-white border-gray-600" data-testid="select-guests">
                                <SelectValue placeholder="人数を選択" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="1">1名</SelectItem>
                              <SelectItem value="2">2名</SelectItem>
                              <SelectItem value="4">4名</SelectItem>
                              <SelectItem value="6">6名</SelectItem>
                              <SelectItem value="8+">8名以上</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="table"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-white font-semibold">テーブル選択</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger className="bg-gray-700 text-white border-gray-600" data-testid="select-table">
                                <SelectValue placeholder="テーブルを選択" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="beast">野獣テーブル</SelectItem>
                              <SelectItem value="senpai">先輩席</SelectItem>
                              <SelectItem value="114514">114514ボックス</SelectItem>
                              <SelectItem value="mad">MAD個室</SelectItem>
                              <SelectItem value="niconico">ニコニコルーム</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                  
                  <FormField
                    control={form.control}
                    name="phone"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-white font-semibold">電話番号 *</FormLabel>
                        <FormControl>
                          <Input 
                            type="tel" 
                            placeholder="114-514-1919" 
                            className="bg-gray-700 text-white border-gray-600" 
                            data-testid="input-phone"
                            {...field} 
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="requests"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-white font-semibold">特別要望</FormLabel>
                        <FormControl>
                          <Textarea 
                            placeholder="野獣の日特典希望、アレルギー等..." 
                            className="bg-gray-700 text-white border-gray-600 h-24" 
                            data-testid="textarea-requests"
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
                    data-testid="button-submit-reservation"
                  >
                    {isSubmitting ? "送信中..." : "いいよ！予約する！"}
                  </Button>
                </form>
              </Form>
            </div>
            
            {/* Reservation Info */}
            <div className="space-y-6">
              {/* Beast Day Campaign */}
              <div className="bg-gradient-to-r from-meme-orange to-dramatic-red rounded-xl p-6 text-white">
                <h3 className="text-xl font-bold mb-4">🔥 Beast Day Campaign</h3>
                <p className="mb-4">8月10日限定！全メニュー114514円引き</p>
                <div className="bg-white/20 rounded-lg p-4">
                  <p className="text-sm">キャンペーンコード: <span className="font-mono font-bold">BEAST810</span></p>
                </div>
              </div>
              
              {/* Availability Calendar */}
              <div className="bg-gray-800 rounded-xl p-6">
                <h3 className="text-xl font-bold text-meme-yellow mb-4">空席状況</h3>
                <div className="grid grid-cols-7 gap-2 mb-4">
                  {['月', '火', '水', '木', '金', '土', '日'].map(day => (
                    <div key={day} className="text-center text-sm text-gray-400 p-2">{day}</div>
                  ))}
                  {Array.from({length: 14}, (_, i) => i + 1).map(day => (
                    <div 
                      key={day} 
                      className={`text-center text-sm p-2 rounded ${
                        day === 10 ? 'bg-beast-day text-white font-bold' : 'bg-gray-700'
                      }`}
                    >
                      {day}
                    </div>
                  ))}
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-green-500 rounded"></div>
                    <span>空席あり</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-yellow-500 rounded"></div>
                    <span>残りわずか</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 bg-beast-day rounded"></div>
                    <span>野獣の日 Special</span>
                  </div>
                </div>
              </div>
              
              {/* Usage Guide */}
              <div className="bg-gray-800 rounded-xl p-6">
                <h3 className="text-xl font-bold text-meme-yellow mb-4">ご利用案内</h3>
                <ul className="space-y-2 text-gray-300">
                  <li className="flex items-center space-x-2">
                    <i className="fas fa-clock text-digital-cyan"></i>
                    <span>予約は2時間制となります</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <i className="fas fa-utensils text-digital-cyan"></i>
                    <span>コース料理のご予約承ります</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <i className="fas fa-birthday-cake text-digital-cyan"></i>
                    <span>記念日プランあり</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <i className="fas fa-music text-digital-cyan"></i>
                    <span>BGMはMAD楽曲をお楽しみください</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}