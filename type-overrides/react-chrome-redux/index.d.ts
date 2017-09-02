import { Action, Middleware, Store as ReduxStore } from 'redux';

declare module 'react-chrome-redux' {
	interface StoreOptions<S> {
		portName: string;
		state?: S;
		extensionId?: string;
	}

	export class Store<S, D=any> {
		constructor(options: StoreOptions<S>);

		ready(cb: () => void): Promise<void>;
		subscribe(listener: () => void): () => void;

		replaceState(state: S): void;
		getState(): S;
		dispatch(data: D): Promise<D>;
	}

	interface WrapStoreOptions {
		portName: string;
		dispatchResponder?: (dispatchResult: any, send: () => void) => void;
	}

	export function wrapStore<S>(store: ReduxStore<S>, options: WrapStoreOptions): void;


	interface Alias<A extends Action, D> {
		(action: A): D;
	}

	type AliasMap<A extends Action, D> = {
		[key: string]: Alias<A, D>
	};

	export function alias<A extends Action, D>(aliases: AliasMap<A, D>): Middleware;
}
