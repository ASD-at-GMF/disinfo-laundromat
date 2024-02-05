<script lang="ts">
	import { cn } from '$utils';
	export let name : string;
  export let value : string = '';
  export let placeholder : string = '';
  export let rows : number  = 4;
  export let cols : number  = 50;
	export let required: boolean = false;
  export let onInputChange : (value: string, name: string) => void = (value: string, name: string) => {};
	let className : string = '';
	export {className as class}

  function handleInputChange(event: Event) {
    const { value } = event.target as HTMLTextAreaElement;
    if (onInputChange) {
      onInputChange(value, name);
    }
  }
</script>


<textarea
	id={name}
	bind:value 
	placeholder={placeholder} 
	rows={rows}
	cols={cols}
	required={required}
	on:input={handleInputChange}
	class={cn('w-full', className)}/>
