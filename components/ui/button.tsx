import { Button as ButtonPrimitive } from "@base-ui/react/button";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva("arena-button", {
  variants: {
    variant: { default: "arena-button-primary", secondary: "arena-button-secondary", ghost: "arena-button-ghost" },
    size: { default: "arena-button-default", lg: "arena-button-large" },
  },
  defaultVariants: { variant: "default", size: "default" },
});

function Button({ className, variant = "default", size = "default", ...props }: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return <ButtonPrimitive className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}

export { Button };
