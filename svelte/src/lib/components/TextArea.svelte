<script lang="ts">
	import { cn } from '$utils';
  export let onInputChange : (value: string, name: string) => void;
	export let name : string;
  export let value : string = '';
  export let placeholder : string = '';
  export let rows : number  = 4;
  export let cols : number  = 50;
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
	bind:value placeholder={placeholder} 
	rows={rows}
	cols={cols}
	on:input={handleInputChange}
	class={cn('w-full', className)}/>
