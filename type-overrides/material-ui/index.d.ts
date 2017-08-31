declare namespace __MaterialUI {
	export interface AppBarProps {
		position?: 'static' | 'fixed' | 'absolute';
		color?: 'inherit' | 'primary' | 'accent' | 'default';
	}

	export namespace Styles {
		export interface MuiThemeProviderProps {
			theme?: MuiTheme;
		}
	}
}

declare module 'material-ui/styles' {
	export function createMuiTheme(theme: object): __MaterialUI.Styles.MuiTheme;
}
