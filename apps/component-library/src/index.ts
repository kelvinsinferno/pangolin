// SPDX-License-Identifier: AGPL-3.0-or-later
// Pangolin component-library public barrel. Imports tokens.css FIRST
// so any downstream consumer that imports `@pangolin/component-library`
// automatically picks up the design-token CSS variables — no separate
// import needed on the consumer side.
import './tokens.css';

// Atomic primitives.
export { Button } from './atomic/Button/Button';
export type { ButtonProps, ButtonVariant, ButtonSize } from './atomic/Button/Button';

export { Input } from './atomic/Input/Input';
export type { InputProps, InputType } from './atomic/Input/Input';

export { Label } from './atomic/Label/Label';
export type { LabelProps } from './atomic/Label/Label';

export { IconButton } from './atomic/IconButton/IconButton';
export type { IconButtonProps, IconButtonSize } from './atomic/IconButton/IconButton';

export { Avatar } from './atomic/Avatar/Avatar';
export type { AvatarProps, AvatarSize } from './atomic/Avatar/Avatar';

export { Spinner } from './atomic/Spinner/Spinner';
export type { SpinnerProps, SpinnerSize } from './atomic/Spinner/Spinner';

export { Badge } from './atomic/Badge/Badge';
export type { BadgeProps, BadgeTone } from './atomic/Badge/Badge';

export { Divider } from './atomic/Divider/Divider';
export type { DividerProps, DividerOrientation } from './atomic/Divider/Divider';

export { Tag } from './atomic/Tag/Tag';
export type { TagProps } from './atomic/Tag/Tag';

export { Code } from './atomic/Code/Code';
export type { CodeProps, CodeVariant } from './atomic/Code/Code';

// Composite components.
export { ListRow } from './composite/ListRow/ListRow';
export type { ListRowProps } from './composite/ListRow/ListRow';

export { Modal } from './composite/Modal/Modal';
export type { ModalProps } from './composite/Modal/Modal';

export { Toast } from './composite/Toast/Toast';
export type { ToastProps, ToastVariant } from './composite/Toast/Toast';

export { PasswordMeter } from './composite/PasswordMeter/PasswordMeter';
export type {
  PasswordMeterProps,
  PasswordStrength,
} from './composite/PasswordMeter/PasswordMeter';

export { SeedPhraseGrid } from './composite/SeedPhraseGrid/SeedPhraseGrid';
export type { SeedPhraseGridProps } from './composite/SeedPhraseGrid/SeedPhraseGrid';

export { Card } from './composite/Card/Card';
export type { CardProps, CardElevation } from './composite/Card/Card';

// Icons.
export * from './icons';
