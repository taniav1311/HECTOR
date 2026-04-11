import { motion } from "framer-motion";
import { ArrowRight, Circle } from "lucide-react";
import { cn } from "@/lib/utils";

function ElegantShape({ className, delay = 0, width = 400, height = 100, rotate = 0, gradient = "from-white/[0.08]" }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -150, rotate: rotate - 15 }}
      animate={{ opacity: 1, y: 0, rotate }}
      transition={{
        duration: 2.4,
        delay,
        ease: [0.23, 0.86, 0.39, 0.96],
        opacity: { duration: 1.2 },
      }}
      className={cn("absolute", className)}
    >
      <motion.div
        animate={{ y: [0, 15, 0] }}
        transition={{ duration: 12, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
        style={{ width, height }}
        className="relative"
      >
        <div
          className={cn(
            "absolute inset-0 rounded-full",
            "bg-gradient-to-r to-transparent",
            gradient,
            "backdrop-blur-[2px] border-2 border-white/[0.15]",
            "shadow-[0_8px_32px_0_rgba(255,255,255,0.1)]",
            "after:absolute after:inset-0 after:rounded-full",
            "after:bg-[radial-gradient(circle_at_50%_50%,rgba(255,255,255,0.2),transparent_70%)]"
          )}
        />
      </motion.div>
    </motion.div>
  );
}

export function HeroGeometric({ title = "HECTOR", subtitle = "Hybrid Explainable CVE-based Threat Observation and Risk-analysis", actionLabel = "Enter Project", onAction }) {
  const fadeUpVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: (i) => ({
      opacity: 1,
      y: 0,
      transition: {
        duration: 1,
        delay: 0.5 + i * 0.2,
        ease: [0.25, 0.4, 0.25, 1],
      },
    }),
  };

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center overflow-hidden bg-[#030303] px-4">
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/[0.08] via-transparent to-rose-500/[0.08] blur-3xl" />

      <div className="absolute inset-0 overflow-hidden">
        <ElegantShape delay={0.3} width={600} height={140} rotate={12} gradient="from-cyan-500/[0.16]" className="left-[-10%] md:left-[-5%] top-[15%] md:top-[20%]" />
        <ElegantShape delay={0.5} width={500} height={120} rotate={-15} gradient="from-rose-500/[0.16]" className="right-[-5%] md:right-[0%] top-[70%] md:top-[75%]" />
        <ElegantShape delay={0.4} width={300} height={80} rotate={-8} gradient="from-violet-500/[0.14]" className="left-[5%] md:left-[10%] bottom-[5%] md:bottom-[10%]" />
        <ElegantShape delay={0.6} width={200} height={60} rotate={20} gradient="from-amber-500/[0.12]" className="right-[15%] md:right-[20%] top-[10%] md:top-[15%]" />
      </div>

      <div className="relative z-10 mx-auto w-full max-w-4xl text-center">
        <motion.div
          custom={0}
          variants={fadeUpVariants}
          initial="hidden"
          animate="visible"
          className="mb-8 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-4 py-1.5"
        >
          <Circle className="h-2 w-2 fill-rose-400 text-rose-400" />
          <span className="text-xs uppercase tracking-[0.24em] text-white/55">Threat intelligence platform</span>
        </motion.div>

        <motion.div custom={1} variants={fadeUpVariants} initial="hidden" animate="visible">
          <h1 className="text-6xl font-black tracking-[0.18em] text-white sm:text-7xl md:text-8xl lg:text-[8.5rem]">
            {title}
          </h1>
        </motion.div>

        <motion.div custom={2} variants={fadeUpVariants} initial="hidden" animate="visible">
          <p className="mx-auto mt-6 max-w-2xl px-4 text-sm leading-7 tracking-wide text-white/55 sm:text-base md:text-lg">
            {subtitle}
          </p>
        </motion.div>

        <motion.div custom={3} variants={fadeUpVariants} initial="hidden" animate="visible" className="mt-10">
          <button
            type="button"
            onClick={onAction}
            className={cn(
              "inline-flex items-center gap-2 rounded-full px-6 py-3 text-sm font-semibold text-white",
              "bg-gradient-to-r from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20",
              "transition-transform duration-200 hover:-translate-y-0.5 hover:shadow-cyan-500/30"
            )}
          >
            {actionLabel}
            <ArrowRight className="h-4 w-4" />
          </button>
        </motion.div>
      </div>

      <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-[#030303] via-transparent to-[#030303]/80" />
    </div>
  );
}