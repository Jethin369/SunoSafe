# Synthetic call scripts for a safe demo

Record these yourself or have a consenting participant read them. Do not imitate a real company using real brand scripts, and do not use real phone numbers, account numbers, OTPs, or personal details. Keep each clip under 30 seconds for easier testing.

## Script A — suspicious credential request (Hinglish)

"Hello sir, main bank verification team se bol raha hoon. Aapka account aaj block ho sakta hai. Verification ke liye apna OTP bataiye. Main aapko ek link bhej raha hoon, us par click karke details confirm kar dijiye."

Expected demonstration: Prisma transcription; credential-request and urgency signals if correctly transcribed; evidence phrases visible; reminder to verify via official channel. The result may vary with the transcription.

## Script B — suspicious remote-access request (Hinglish)

"Sir, refund ke liye AnyDesk app install kariye aur screen share kijiye. Main aapko guide karunga. Jaldi karna hoga, warna request cancel ho jayegi."

Expected demonstration: remote-access signal; possible urgency signal; next-step guidance not to install remote-access software at the caller's request.

## Script C — benign delivery confirmation

"Namaste, aapki delivery kal subah das baje ke aas-paas aa jayegi. Aapko abhi koi payment karne ki zaroorat nahi hai. Agar timing change hui to hum aapko message bhej denge."

Expected demonstration: ideally no warning signals. This is important to show the product does not automatically label every call as suspicious.

## Script D — benign security advice

"Customer awareness ke liye ek reminder hai: apna OTP, PIN ya password kisi ke saath share mat kijiye. Agar aapko bank se related koi doubt hai, to official app ya website par diya gaya number use kijiye."

Expected demonstration: the analyzer should avoid interpreting advice against sharing credentials as a credential request. If the transcript differs, record the exact failure and tune the rule only when justified.

## Recording checklist

- Use a quiet room for baseline recordings, then test a separate version with light background noise.
- Speak naturally and include normal pauses; don't rush to make the model fail.
- Use separate audio files per script. Note whether the transcript matches the spoken words before evaluating the warning-sign rules.
- Don't publicly upload recordings of other people without their permission.
