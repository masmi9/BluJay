declare module 'react-window' {
  import * as React from 'react';

  export interface ListChildComponentProps {
    index: number;
    style: React.CSSProperties;
    data?: any;
    isScrolling?: boolean;
  }

  export interface FixedSizeListProps {
    height: number;
    itemCount: number;
    itemSize: number;
    width: number | string;
    itemData?: any;
    overscanCount?: number;
    children: (props: ListChildComponentProps) => React.ReactElement | null;
  }

  export const FixedSizeList: React.ForwardRefExoticComponent<FixedSizeListProps & React.RefAttributes<any>>;
  export { FixedSizeList as List };
}


