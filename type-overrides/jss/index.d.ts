declare module 'jss' {
	export const getDynamicStyles: any;
	export const SheetsRegistry: any;
	export const SheetsManager: any;
	export const RuleList: any;
	export const sheets: any;

	type Rule = any;
	type JssStyle = string | object | object[];
	type generateClassName = (rule: Rule, sheet?: StyleSheet) => string;
	type createGenerateClassName = () => generateClassName;
	type RendererClass = new () => Renderer;

	interface Renderer {
		constructor(sheet?: StyleSheet): Renderer;
		setStyle(rule: HTMLElement | CSSStyleRule, prop: string, value: string): boolean;
		getStyle(rule: HTMLElement | CSSStyleRule, prop: string): string;
		setSelector(rule: CSSStyleRule, selectorText: string): boolean;
		getSelector(rule: CSSStyleRule): string;
		attach(): void;
		detach(): void;
		deploy(sheet: StyleSheet): void;
		insertRule(rule: Rule): false | CSSStyleRule;
		deleteRule(rule: CSSStyleRule): boolean;
		getRules(): CSSRuleList | void;
	}

	interface RuleOptions {
		selector?: string;
		sheet?: StyleSheet;
		index?: number;
		classes: Object;
		jss: Jss;
		generateClassName: generateClassName;
		Renderer: RendererClass;
	}

	interface Plugin {
		onCreateRule?: (name: string, decl: JssStyle, options: RuleOptions) => Rule|null;
		onProcessRule?: (rule: Rule, sheet?: StyleSheet) => void;
		onProcessStyle?: (style: JssStyle, rule: Rule, sheet?: StyleSheet) => JssStyle;
		onProcessSheet?: (sheet?: StyleSheet) => void;
		onChangeValue?: (value: string, prop: string, rule: Rule) => string;
	}

	type InsertionPoint = string | HTMLElement;

	interface JssOptions {
		createGenerateClassName?: createGenerateClassName;
		plugins?: Plugin[];
		insertionPoint?: InsertionPoint;
		Renderer?: RendererClass;
		virtual?: boolean;
	}

	interface StyleSheetFactoryOptions {
		media?: string;
		meta?: string;
		index?: number;
		link?: boolean;
		element?: HTMLStyleElement;
		generateClassName?: generateClassName;
	}

	interface Jss {
		createStyleSheet(styles: object, options?: StyleSheetFactoryOptions);
	}

	export function create(options?: JssOptions): Jss;

	const jss: Jss;
	export default jss;
}
